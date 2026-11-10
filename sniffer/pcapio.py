"""PCAP / PCAPNG I/O with explicit size limits and transactional exports."""
import os
from pathlib import Path
import struct
import tempfile

from .protocols import decode_packet

MAX_PACKET = 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_PACKETS = 50000
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


class CaptureFileError(ValueError):
    pass


def exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise CaptureFileError("捕获文件被截断")
    return data


def read_capture(path):
    path = Path(path)
    if path.stat().st_size > MAX_FILE:
        raise CaptureFileError("文件超过 256 MiB，请先分割捕获文件")
    with path.open("rb") as f:
        magic = exact(f, 4)
        if magic == b"\x0a\x0d\x0d\x0a":
            f.seek(0)
            iterator = _read_ng(f)
        else:
            iterator = _read_pcap(f, magic)
        packets, total = [], 0
        for ts, raw, wire, link in iterator:
            if len(packets) >= MAX_PACKETS:
                raise CaptureFileError("文件超过 50,000 包，请先分割")
            total += len(raw)
            if total > MAX_CAPTURE_BYTES:
                raise CaptureFileError("捕获数据超过 64 MiB，请先分割")
            packets.append(decode_packet(raw, ts, wire, link, len(packets)+1))
        return packets


def _read_pcap(f, magic):
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if magic not in formats:
        raise CaptureFileError("文件不是 PCAP 或 PCAPNG")
    endian, scale = formats[magic]
    major, minor, zone, sigfigs, snaplen, network = struct.unpack(endian+"HHiIII", exact(f, 20))
    if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_PACKET:
        raise CaptureFileError("PCAP 版本或 snaplen 不受支持")
    linktype = network & 0xFFFF
    while True:
        header = f.read(16)
        if not header:
            return
        if len(header) != 16:
            raise CaptureFileError("PCAP 包头被截断")
        sec, frac, caplen, wire = struct.unpack(endian+"IIII", header)
        if caplen > MAX_PACKET or caplen > snaplen or caplen > wire or frac >= scale:
            raise CaptureFileError("PCAP 包长度或时间戳无效")
        yield sec + frac/scale, exact(f, caplen), wire, linktype


def _options(body, endian):
    offset = 0
    while offset < len(body):
        if offset+4 > len(body):
            raise CaptureFileError("PCAPNG option 头被截断")
        typ, size = struct.unpack_from(endian+"HH", body, offset)
        offset += 4
        if typ == 0:
            if size:
                raise CaptureFileError("PCAPNG end option 长度无效")
            return
        padded = (size+3) & ~3
        if offset+padded > len(body):
            raise CaptureFileError("PCAPNG option 被截断")
        yield typ, body[offset:offset+size]
        offset += padded


def _read_ng(f):
    endian, interfaces = None, []
    while True:
        header = f.read(8)
        if not header:
            return
        if len(header) != 8:
            raise CaptureFileError("PCAPNG block header 被截断")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            bom = exact(f, 4)
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
            if not endian:
                raise CaptureFileError("PCAPNG byte-order magic 无效")
            size = struct.unpack(endian+"I", header[4:])[0]
            if size < 28 or size % 4 or size > MAX_PACKET+65536:
                raise CaptureFileError("PCAPNG section 长度无效")
            rest = exact(f, size-12)
            if struct.unpack(endian+"I", rest[-4:])[0] != size:
                raise CaptureFileError("PCAPNG block 尾长度不匹配")
            if struct.unpack_from(endian+"HH", rest) != (1, 0):
                raise CaptureFileError("PCAPNG section 版本不受支持")
            interfaces = []
            continue
        if endian is None:
            raise CaptureFileError("PCAPNG 缺少 section header")
        typ, size = struct.unpack(endian+"II", header)
        if size < 12 or size % 4 or size > MAX_PACKET+65536:
            raise CaptureFileError("PCAPNG block 长度无效")
        block = exact(f, size-8)
        if struct.unpack(endian+"I", block[-4:])[0] != size:
            raise CaptureFileError("PCAPNG block 尾长度不匹配")
        body = block[:-4]
        if typ == 1:
            if len(interfaces) >= 1024:
                raise CaptureFileError("PCAPNG 每个 section 的接口数超过 1024")
            if len(body) < 8:
                raise CaptureFileError("PCAPNG interface 被截断")
            link, _, snaplen = struct.unpack_from(endian+"HHI", body)
            scale, t_offset = 1e6, 0
            for key, value in _options(body[8:], endian):
                if key == 9 and len(value) == 1:
                    exponent = value[0] & 127
                    scale = (2 if value[0] & 128 else 10) ** exponent
                elif key == 14 and len(value) == 8:
                    t_offset = struct.unpack(endian+"q", value)[0]
            interfaces.append((link, snaplen, scale, t_offset))
        elif typ == 6:
            if len(body) < 20:
                raise CaptureFileError("PCAPNG packet header 被截断")
            interface, hi, lo, caplen, wire = struct.unpack_from(endian+"5I", body)
            if interface >= len(interfaces):
                raise CaptureFileError("PCAPNG interface ID 无效")
            link, snaplen, scale, t_offset = interfaces[interface]
            padded = (caplen+3) & ~3
            if caplen > MAX_PACKET or caplen > wire or (snaplen and caplen > snaplen) or 20+padded > len(body):
                raise CaptureFileError("PCAPNG packet 长度无效")
            yield ((hi << 32) | lo)/scale+t_offset, body[20:20+caplen], wire, link
        elif typ in (2, 3):
            raise CaptureFileError("PCAPNG 仅支持 Enhanced Packet Block；请转换旧式 Packet / Simple Packet Block")


def _atomic_write(path, callback):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.name+".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            callback(f)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def write_capture(path, packets):
    packets = list(packets)
    if str(path).lower().endswith(".pcapng"):
        return _atomic_write(path, lambda f: _write_ng(f, packets))
    links = {p.linktype for p in packets}
    if len(links) > 1:
        raise CaptureFileError("PCAP 只支持一种链路类型；混合接口请保存为 .pcapng")
    def write(f):
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, MAX_PACKET, next(iter(links),1)))
        for p in packets:
            total_us = round(p.timestamp * 1e6)
            sec, usec = divmod(total_us, 1000000)
            f.write(struct.pack("<IIII", sec, usec, len(p.raw), p.wire_length))
            f.write(p.raw)
    _atomic_write(path, write)


def _write_ng(f, packets):
    def block(typ, body):
        body += b"\0" * (-len(body) % 4)
        size = len(body)+12
        f.write(struct.pack("<II", typ, size)+body+struct.pack("<I", size))
    block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    links = list(dict.fromkeys(p.linktype for p in packets)) or [1]
    for link in links:
        block(1, struct.pack("<HHI", link, 0, MAX_PACKET))
    for p in packets:
        ticks = round(p.timestamp*1e6)
        block(6, struct.pack("<5I", links.index(p.linktype), ticks >> 32, ticks & 0xFFFFFFFF,
                             len(p.raw), p.wire_length)+p.raw)

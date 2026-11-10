"""Bounds-checked protocol parsing. No Scapy, tshark or Wireshark dependency."""
import ipaddress
import re
import struct

from .model import Layer, Packet


class DecodeError(ValueError):
    pass


def require(data, offset, size, what):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise DecodeError(f"{what}: 截断，需要 {size} 字节，剩余 {max(0, len(data)-offset)}")


def u16(data, offset=0):
    require(data, offset, 2, "uint16")
    return struct.unpack_from("!H", data, offset)[0]


def mac(data):
    return ":".join(f"{v:02x}" for v in data)


def dns_name(data, offset):
    labels, seen, end = [], set(), None
    for _ in range(128):
        require(data, offset, 1, "DNS name")
        if offset in seen:
            raise DecodeError("DNS 压缩指针循环")
        seen.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            require(data, offset, 2, "DNS pointer")
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | data[offset + 1]
            continue
        if size & 0xC0:
            raise DecodeError("DNS 标签编码无效")
        offset += 1
        if not size:
            return ".".join(labels) or ".", end if end is not None else offset
        require(data, offset, size, "DNS label")
        labels.append(data[offset:offset + size].decode("ascii", "replace"))
        if sum(len(x) + 1 for x in labels) > 255:
            raise DecodeError("DNS 名称超过 255 字节")
        offset += size
    raise DecodeError("DNS 名称解析层数超限")


def parse_dns(data):
    require(data, 0, 12, "DNS header")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", data)
    if qd + an + ns + ar > 256:
        raise DecodeError("DNS 记录数量超过解析上限 256")
    fields = {"Transaction ID": f"0x{ident:04x}", "Response": bool(flags & 0x8000),
              "Opcode": (flags >> 11) & 15, "Rcode": flags & 15,
              "Questions": qd, "Answers": an, "Authority": ns, "Additional": ar}
    offset, questions, answers = 12, [], []
    types = {1: "A", 28: "AAAA", 5: "CNAME", 2: "NS", 12: "PTR", 16: "TXT", 15: "MX", 65: "HTTPS"}
    for i in range(qd):
        name, offset = dns_name(data, offset)
        require(data, offset, 4, "DNS question")
        typ, cls = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append(f"{name} {types.get(typ, typ)}")
        fields[f"Question {i+1}"] = f"{name} / {types.get(typ, typ)} / class {cls}"
    for i in range(an + ns + ar):
        name, offset = dns_name(data, offset)
        require(data, offset, 10, "DNS RR")
        typ, cls, ttl, length = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        require(data, offset, length, "DNS RDATA")
        value = data[offset:offset+length].hex()
        if (typ == 1 and length == 4) or (typ == 28 and length == 16):
            value = str(ipaddress.ip_address(data[offset:offset+length]))
        elif typ in (2, 5, 12):
            value, consumed = dns_name(data, offset)
            if consumed > offset + length:
                raise DecodeError("DNS RDATA name 超出记录边界")
        fields[f"Record {i+1}"] = f"{name} {types.get(typ, typ)} {value} TTL={ttl}"
        if i < an:
            answers.append(value)
        offset += length
    info = ("Response " if flags & 0x8000 else "Query ") + ", ".join(questions)
    if answers:
        info += " → " + ", ".join(answers)
    return fields, info


HTTP_REQUEST = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) [^\r\n ]+ HTTP/1\.[01]\r\n")
HTTP_RESPONSE = re.compile(rb"^HTTP/1\.[01] [1-5][0-9]{2} [^\r\n]*\r\n")


def parse_http(data):
    if not (HTTP_REQUEST.match(data) or HTTP_RESPONSE.match(data)):
        return None
    header_end = data.find(b"\r\n\r\n", 0, 65536)
    head = data[:header_end if header_end >= 0 else min(len(data), 65536)]
    lines = head.decode("iso-8859-1").split("\r\n")
    fields = {"Start line": lines[0], "Headers complete": header_end >= 0}
    for i, line in enumerate(lines[1:]):
        if ":" in line:
            key, value = line.split(":", 1)
            fields[f"{key.strip()} [{i+1}]"] = value.strip()
    fields["Captured body bytes"] = len(data)-header_end-4 if header_end >= 0 else 0
    return fields, lines[0]


def parse_tls(data):
    if len(data) < 5 or data[0] not in (20, 21, 22, 23) or data[1] != 3 or data[2] > 4:
        return None
    length = u16(data, 3)
    if length > 18432:
        return None
    types = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data"}
    fields = {"Content type": types[data[0]], "Record version": f"0x{u16(data, 1):04x}",
              "Record length": length, "Record complete": len(data) >= length + 5}
    info = "TLS " + types[data[0]]
    if data[0] == 22 and length >= 4 and len(data) >= length + 5 and data[5] == 1:
        hello_size = int.from_bytes(data[6:9], "big")
        body = data[9:9+hello_size]
        require(data[5:5+length], 4, hello_size, "TLS ClientHello")
        require(body, 0, 35, "TLS ClientHello")
        offset = 35 + body[34]
        require(body, offset, 2, "TLS cipher suites")
        offset += 2 + u16(body, offset)
        require(body, offset, 1, "TLS compression")
        offset += 1 + body[offset]
        require(body, 0, offset, "TLS ClientHello fields")
        info = "TLS ClientHello"
        if offset < len(body):
            ext_size = u16(body, offset)
            offset += 2
            require(body, offset, ext_size, "TLS extensions")
            end = offset + ext_size
            while offset < end:
                require(body[:end], offset, 4, "TLS extension header")
                typ, size = struct.unpack_from("!HH", body, offset)
                offset += 4
                require(body[:end], offset, size, "TLS extension")
                if typ == 0:
                    sni = body[offset:offset+size]
                    names_size = u16(sni)
                    require(sni, 2, names_size, "TLS SNI list")
                    pos = 2
                    while pos < 2 + names_size:
                        require(sni[:2+names_size], pos, 3, "TLS SNI header")
                        name_type, name_len = sni[pos], u16(sni, pos+1)
                        pos += 3
                        require(sni[:2+names_size], pos, name_len, "TLS SNI hostname")
                        if name_type == 0:
                            fields["Server Name (SNI)"] = sni[pos:pos+name_len].decode("ascii", "replace")
                            info += " SNI=" + fields["Server Name (SNI)"]
                        pos += name_len
                offset += size
    return fields, info


def decode_packet(raw, timestamp=0.0, wire_length=None, linktype=1, number=1):
    p = Packet(number, timestamp, bytes(raw), len(raw) if wire_length is None else wire_length, linktype)
    p.layers.append(Layer("Frame", {"Number": number, "Timestamp": f"{timestamp:.6f}",
                                  "Captured bytes": len(raw), "Wire bytes": p.wire_length,
                                  "Link type": linktype}, 0, len(raw)))
    if p.wire_length > len(raw):
        p.warnings.append("捕获长度小于线上长度（snaplen 截断）")
    try:
        _decode(p)
    except (DecodeError, struct.error, ValueError) as exc:
        p.warnings.append(str(exc))
        p.info = (p.info + " | " if p.info else "") + "Malformed / truncated"
    if p.warnings:
        p.layers.append(Layer("Diagnostics", {str(i+1): w for i, w in enumerate(p.warnings)}))
    return p


def _decode(p):
    data, offset, ethertype = p.raw, 0, None
    if p.linktype == 1:
        require(data, 0, 14, "Ethernet")
        ethertype = u16(data, 12)
        p.src, p.dst = mac(data[6:12]), mac(data[0:6])
        p.protocol = "Ethernet"
        p.layers.append(Layer("Ethernet", {"Source": p.src, "Destination": p.dst,
                                           "EtherType": f"0x{ethertype:04x}"}, 0, 14))
        offset = 14
        for _ in range(4):
            if ethertype not in (0x8100, 0x88A8, 0x9100):
                break
            require(data, offset, 4, "802.1Q")
            tci, ethertype = struct.unpack_from("!HH", data, offset)
            p.layers.append(Layer("VLAN", {"ID": tci & 4095, "Priority": tci >> 13}, offset, offset+4))
            offset += 4
    elif p.linktype in (0, 108):
        require(data, 0, 4, "Loopback")
        family = int.from_bytes(data[:4], "big" if p.linktype == 108 else "little")
        if family not in (2, 10, 23, 24, 28, 30):
            family = int.from_bytes(data[:4], "big")
        ethertype = 0x0800 if family == 2 else 0x86DD if family in (10, 23, 24, 28, 30) else 0
        offset = 4
        p.layers.append(Layer("Loopback", {"Family": family}, 0, 4))
    elif p.linktype in (12, 101, 228, 229):
        require(data, 0, 1, "Raw IP")
        ethertype = 0x0800 if data[0] >> 4 == 4 else 0x86DD if data[0] >> 4 == 6 else 0
    elif p.linktype in (113, 276):
        size = 16 if p.linktype == 113 else 20
        require(data, 0, size, "Linux cooked capture")
        ethertype = u16(data, 14 if p.linktype == 113 else 0)
        offset = size
        p.layers.append(Layer("Linux SLL", {"Protocol": f"0x{ethertype:04x}"}, 0, size))
    else:
        p.info = f"Unsupported link type {p.linktype}"
        return
    if ethertype == 0x0806:
        require(data, offset, 8, "ARP")
        htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, offset)
        require(data, offset+8, 2*(hlen+plen), "ARP addresses")
        fields = {"Hardware type": htype, "Protocol type": f"0x{ptype:04x}", "Operation": op}
        if ptype == 0x0800 and plen == 4:
            p.src = str(ipaddress.ip_address(data[offset+8+hlen:offset+8+hlen+4]))
            p.dst = str(ipaddress.ip_address(data[offset+8+2*hlen+plen:offset+8+2*(hlen+plen)]))
            fields.update({"Sender IP": p.src, "Target IP": p.dst})
        p.protocol, p.info = "ARP", f"{'Who has' if op == 1 else 'Reply'} {p.dst} / sender {p.src}"
        p.layers.append(Layer("ARP", fields, offset, offset+8+2*(hlen+plen)))
        return
    fragmented = False
    if ethertype == 0x0800:
        require(data, offset, 20, "IPv4")
        ihl = (data[offset] & 15)*4
        if data[offset] >> 4 != 4 or ihl < 20:
            raise DecodeError("IPv4 version / IHL 无效")
        require(data, offset, ihl, "IPv4 options")
        total = u16(data, offset+2)
        if total < ihl:
            raise DecodeError("IPv4 total length 小于头部长度")
        fragment = u16(data, offset+6)
        fragmented = bool(fragment & 0x3FFF)
        proto = data[offset+9]
        p.src, p.dst = str(ipaddress.ip_address(data[offset+12:offset+16])), str(ipaddress.ip_address(data[offset+16:offset+20]))
        p.ip_version, p.protocol = 4, "IPv4"
        p.layers.append(Layer("IPv4", {"Source": p.src, "Destination": p.dst, "Header length": ihl,
            "Total length": total, "TTL": data[offset+8], "Protocol": proto, "ID": u16(data, offset+4),
            "DF": bool(fragment & 0x4000), "MF": bool(fragment & 0x2000), "Fragment offset": (fragment & 8191)*8}, offset, offset+ihl))
        if offset + total > len(data):
            p.warnings.append("IPv4 数据报被截断")
        data, offset = data[:offset+total], offset+ihl
    elif ethertype == 0x86DD:
        require(data, offset, 40, "IPv6")
        if data[offset] >> 4 != 6:
            raise DecodeError("IPv6 version 无效")
        size, proto = u16(data, offset+4), data[offset+6]
        p.src, p.dst = str(ipaddress.ip_address(data[offset+8:offset+24])), str(ipaddress.ip_address(data[offset+24:offset+40]))
        p.ip_version, p.protocol = 6, "IPv6"
        p.layers.append(Layer("IPv6", {"Source": p.src, "Destination": p.dst, "Payload length": size,
             "Next header": proto, "Hop limit": data[offset+7], "Flow label": int.from_bytes(data[offset:offset+4], "big") & 0xFFFFF}, offset, offset+40))
        if size == 0 and len(data) > offset + 40:
            p.info = "IPv6 jumbogram: 未实现 Jumbo Payload 选项"
            return
        if offset + 40 + size > len(data):
            p.warnings.append("IPv6 数据报被截断")
        data, offset = data[:offset+40+size], offset+40
        for _ in range(16):
            if proto not in (0, 43, 44, 51, 60):
                break
            require(data, offset, 2, "IPv6 extension")
            current, proto = proto, data[offset]
            size = 8 if current == 44 else (data[offset+1]+2)*4 if current == 51 else (data[offset+1]+1)*8
            require(data, offset, size, "IPv6 extension")
            fields = {"Type": current, "Next header": proto, "Length": size}
            if current == 44:
                frag = u16(data, offset+2)
                fragmented = bool(frag & 0xFFF9)
                fields.update({"Fragment offset": frag & 0xFFF8, "More fragments": bool(frag & 1)})
            p.layers.append(Layer("IPv6 extension", fields, offset, offset+size))
            offset += size
            if fragmented:
                break
        else:
            raise DecodeError("IPv6 扩展头超过 16 层")
    else:
        p.info = f"EtherType 0x{ethertype:04x}"
        return
    if fragmented:
        p.info = "IP fragment（保留原始片段，不进行 IP 分片重组）"
        return
    if proto == 6:
        require(data, offset, 20, "TCP")
        p.sport, p.dport, p.seq, p.ack = struct.unpack_from("!HHII", data, offset)
        hlen, p.flags = (data[offset+12] >> 4)*4, ((data[offset+12] & 1) << 8) | data[offset+13]
        if hlen < 20:
            raise DecodeError("TCP data offset 无效")
        require(data, offset, hlen, "TCP options")
        p.transport = p.protocol = "TCP"
        flagtext = ",".join(name for mask, name in [(2,"SYN"),(16,"ACK"),(1,"FIN"),(4,"RST"),(8,"PSH"),(32,"URG"),(64,"ECE"),(128,"CWR")] if p.flags & mask)
        p.layers.append(Layer("TCP", {"Source port": p.sport, "Destination port": p.dport, "Sequence": p.seq,
            "Acknowledgment": p.ack, "Flags": flagtext, "Header length": hlen, "Window": u16(data, offset+14),
            "Checksum": f"0x{u16(data, offset+16):04x}", "Options": data[offset+20:offset+hlen].hex()}, offset, offset+hlen))
        p.payload = data[offset+hlen:]
        p.info = f"{p.sport} → {p.dport} [{flagtext}] Seq={p.seq} Ack={p.ack} Len={len(p.payload)}"
        app_offset = offset+hlen
        result = parse_http(p.payload)
        if result:
            p.protocol = "HTTP"
        else:
            result = parse_tls(p.payload)
            if result:
                p.protocol = "TLS"
        if result:
            fields, p.info = result
            p.layers.append(Layer(p.protocol, fields, app_offset, len(data)))
        elif (p.sport == 53 or p.dport == 53) and len(p.payload) >= 2:
            dnslen = u16(p.payload)
            require(p.payload, 2, dnslen, "DNS over TCP")
            fields, p.info = parse_dns(p.payload[2:2+dnslen])
            p.protocol = "DNS"
            p.layers.append(Layer("DNS", fields, app_offset+2, app_offset+2+dnslen))
    elif proto == 17:
        require(data, offset, 8, "UDP")
        p.sport, p.dport, size, checksum = struct.unpack_from("!4H", data, offset)
        if size < 8:
            raise DecodeError("UDP length 小于 8")
        p.protocol = p.transport = "UDP"
        p.layers.append(Layer("UDP", {"Source port": p.sport, "Destination port": p.dport, "Length": size,
                                      "Checksum": f"0x{checksum:04x}"}, offset, offset+8))
        if offset + size > len(data):
            p.warnings.append("UDP 数据被截断")
        p.payload = data[offset+8:offset+size]
        p.info = f"{p.sport} → {p.dport} Len={len(p.payload)}"
        if p.sport in (53,5353) or p.dport in (53,5353):
            fields, p.info = parse_dns(p.payload)
            p.protocol = "DNS"
            p.layers.append(Layer("DNS", fields, offset+8, min(len(data),offset+size)))
    elif proto in (1, 58):
        require(data, offset, 4, "ICMP")
        typ, code, checksum = struct.unpack_from("!BBH", data, offset)
        p.protocol = p.transport = "ICMP" if proto == 1 else "ICMPv6"
        names = ({0:"Echo reply",8:"Echo request",3:"Destination unreachable",11:"Time exceeded"} if proto == 1
                 else {128:"Echo request",129:"Echo reply",135:"Neighbor solicitation",136:"Neighbor advertisement",1:"Destination unreachable"})
        fields = {"Type": typ, "Code": code, "Checksum": f"0x{checksum:04x}"}
        if typ in ((0,8) if proto == 1 else (128,129)):
            require(data, offset, 8, "ICMP echo")
            fields.update({"Identifier": u16(data,offset+4), "Sequence":u16(data,offset+6)})
        p.info = f"{names.get(typ,'Type '+str(typ))} Code={code}"
        p.payload = data[offset+4:]
        p.layers.append(Layer(p.protocol, fields, offset, len(data)))
    else:
        p.info = f"IP protocol / next header {proto}"


def hexdump(data, limit=65536):
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        row = data[offset:offset+16]
        hexpart = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset:04x}  {hexpart:<47}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"… 显示前 {limit} 字节；导出文件包含完整捕获数据")
    return "\n".join(lines)

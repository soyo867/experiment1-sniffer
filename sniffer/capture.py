"""Direct ctypes bindings to Npcap/libpcap and a bounded capture worker.

The handle is owned, polled and closed by exactly one worker. Nonblocking mode
allows stop even when the interface receives no packets.
"""
import ctypes as C
import ctypes.util
from dataclasses import dataclass
import os
from pathlib import Path
import queue
import socket
import threading
import time

from .protocols import decode_packet
from .pcapio import MAX_PACKET


class CaptureError(RuntimeError):
    pass


class _Timeval(C.Structure):
    _fields_ = [("tv_sec",C.c_long),("tv_usec",C.c_long)]


class _Header(C.Structure):
    _fields_ = [("ts",_Timeval),("caplen",C.c_uint32),("length",C.c_uint32)]


class _If(C.Structure):
    pass


_If._fields_ = [("next",C.POINTER(_If)),("name",C.c_char_p),("description",C.c_char_p),
               ("addresses",C.c_void_p),("flags",C.c_uint)]


class _Bpf(C.Structure):
    _fields_ = [("length",C.c_uint),("insns",C.c_void_p)]


class _Stats(C.Structure):
    _fields_ = [("received",C.c_uint),("dropped",C.c_uint),("interface_dropped",C.c_uint),("captured",C.c_uint)]


@dataclass
class Interface:
    name: str
    description: str
    loopback: bool

    @property
    def label(self):
        return ("[Loopback] " if self.loopback else "") + self.description + "  ·  " + self.name


class Pcap:
    def __init__(self):
        self.dll_directory = None
        try:
            if os.name == "nt":
                directory = Path(os.environ.get("SystemRoot",r"C:\Windows")) / "System32" / "Npcap"
                if not (directory / "wpcap.dll").is_file():
                    raise CaptureError("未检测到 Npcap。请从 https://npcap.com 安装后点击“刷新网卡”。离线样例可直接使用。")
                self.dll_directory = os.add_dll_directory(str(directory))
                self.lib = C.CDLL(str(directory / "wpcap.dll"))
            else:
                name = ctypes.util.find_library("pcap")
                if not name:
                    raise CaptureError("未找到 libpcap，请安装系统 libpcap 运行库")
                self.lib = C.CDLL(name)
        except OSError as exc:
            raise CaptureError(f"加载 Npcap/libpcap 失败：{exc}") from exc
        self._bind()
        if hasattr(self.lib, "pcap_init"):
            self.lib.pcap_init.argtypes = [C.c_uint,C.c_char_p]
            self.lib.pcap_init.restype = C.c_int
            err = C.create_string_buffer(256)
            if self.lib.pcap_init(1, err) != 0:
                raise CaptureError(err.value.decode("utf-8","replace"))

    def _bind(self):
        signatures = {
            "pcap_findalldevs": ([C.POINTER(C.POINTER(_If)),C.c_char_p],C.c_int),
            "pcap_freealldevs": ([C.POINTER(_If)],None),
            "pcap_open_live": ([C.c_char_p,C.c_int,C.c_int,C.c_int,C.c_char_p],C.c_void_p),
            "pcap_close": ([C.c_void_p],None),
            "pcap_datalink": ([C.c_void_p],C.c_int),
            "pcap_setnonblock": ([C.c_void_p,C.c_int,C.c_char_p],C.c_int),
            "pcap_next_ex": ([C.c_void_p,C.POINTER(C.POINTER(_Header)),C.POINTER(C.POINTER(C.c_ubyte))],C.c_int),
            "pcap_compile": ([C.c_void_p,C.POINTER(_Bpf),C.c_char_p,C.c_int,C.c_uint32],C.c_int),
            "pcap_setfilter": ([C.c_void_p,C.POINTER(_Bpf)],C.c_int),
            "pcap_freecode": ([C.POINTER(_Bpf)],None),
            "pcap_geterr": ([C.c_void_p],C.c_char_p),
            "pcap_stats": ([C.c_void_p,C.POINTER(_Stats)],C.c_int),
            "pcap_lib_version": ([],C.c_char_p),
            "pcap_open_dead": ([C.c_int,C.c_int],C.c_void_p),
            "pcap_offline_filter": ([C.POINTER(_Bpf),C.POINTER(_Header),C.POINTER(C.c_ubyte)],C.c_uint),
        }
        for name,(args,restype) in signatures.items():
            fn = getattr(self.lib,name)
            fn.argtypes,fn.restype = args,restype

    @property
    def version(self):
        return self.lib.pcap_lib_version().decode("utf-8","replace")

    def interfaces(self):
        first, err = C.POINTER(_If)(), C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(first),err) != 0:
            raise CaptureError(err.value.decode("utf-8","replace"))
        result = []
        try:
            current = first
            while current:
                item = current.contents
                name = item.name.decode("utf-8","replace")
                description = (item.description or item.name).decode("utf-8","replace")
                result.append(Interface(name,description,bool(item.flags & 1) or "loopback" in name.lower()))
                current = item.next
        finally:
            self.lib.pcap_freealldevs(first)
        return result

    def error(self, handle):
        return self.lib.pcap_geterr(handle).decode("utf-8","replace")

    def set_filter(self, handle, expression):
        if not expression.strip():
            return
        program = _Bpf()
        if self.lib.pcap_compile(handle,C.byref(program),expression.encode("utf-8"),1,0xFFFFFFFF) != 0:
            raise CaptureError("BPF 过滤器无效："+self.error(handle))
        try:
            if self.lib.pcap_setfilter(handle,C.byref(program)) != 0:
                raise CaptureError("BPF 设置失败："+self.error(handle))
        finally:
            self.lib.pcap_freecode(C.byref(program))


class ProcessResolver:
    """Optional psutil socket snapshots, exact TCP tuple matching only."""
    def __init__(self):
        self.mapping, self.updated, self.status = {}, 0.0, "进程关联未启用"
        try:
            import psutil
            self.psutil = psutil
            self.status = "进程关联：周期性 socket 快照"
        except ImportError:
            self.psutil = None

    def refresh(self):
        if self.psutil is None or time.monotonic()-self.updated < 1.0:
            return
        self.updated = time.monotonic()
        try:
            result, names = {}, {}
            for conn in self.psutil.net_connections(kind="tcp"):
                if not conn.laddr or not conn.raddr or conn.pid is None:
                    continue
                if conn.pid not in names:
                    try:
                        names[conn.pid] = f"{self.psutil.Process(conn.pid).name()} ({conn.pid})"
                    except self.psutil.Error:
                        names[conn.pid] = f"PID {conn.pid}"
                key = (conn.laddr.ip,conn.laddr.port,conn.raddr.ip,conn.raddr.port)
                result[key] = names[conn.pid]
            self.mapping = result
        except (self.psutil.Error,OSError) as exc:
            self.status = "进程快照不可用："+str(exc)

    def resolve(self, p):
        if p.transport != "TCP":
            return ""
        key = (p.src,p.sport,p.dst,p.dport)
        reverse = (p.dst,p.dport,p.src,p.sport)
        names = set(filter(None,(self.mapping.get(key),self.mapping.get(reverse))))
        return "; ".join(sorted(names))


class CaptureSession:
    def __init__(self, pcap, interface, bpf="", promisc=False):
        self.pcap, self.interface, self.bpf, self.promisc = pcap, interface, bpf, promisc
        self.packets, self.events = queue.Queue(maxsize=2048), queue.SimpleQueue()
        self.stop_event = threading.Event()
        self.dropped, self.count, self.stats = 0, 0, {}
        self.thread = threading.Thread(target=self._run, name="pcap-capture", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def _run(self):
        api, handle = self.pcap.lib, None
        try:
            error = C.create_string_buffer(256)
            handle = api.pcap_open_live(self.interface.name.encode("utf-8"),65535,int(self.promisc),50,error)
            if not handle:
                raise CaptureError(error.value.decode("utf-8","replace"))
            linktype = api.pcap_datalink(handle)
            self.pcap.set_filter(handle,self.bpf)
            if api.pcap_setnonblock(handle,1,error) != 0:
                raise CaptureError(error.value.decode("utf-8","replace"))
            self.events.put(("started", {"linktype":linktype,"interface":self.interface.description}))
            resolver = ProcessResolver()
            header, data = C.POINTER(_Header)(), C.POINTER(C.c_ubyte)()
            last_stats = 0
            while not self.stop_event.is_set():
                now = time.monotonic()
                if now-last_stats >= 1:
                    resolver.refresh()
                    stats = _Stats()
                    if api.pcap_stats(handle,C.byref(stats)) == 0:
                        self.stats = {"received":stats.received,"kernel_dropped":stats.dropped,
                                      "interface_dropped":stats.interface_dropped,"queue_dropped":self.dropped}
                    self.events.put(("stats",dict(self.stats)))
                    last_stats = now
                code = api.pcap_next_ex(handle,C.byref(header),C.byref(data))
                if code == 0:
                    self.stop_event.wait(0.01)
                    continue
                if code == -2:
                    break
                if code == -1:
                    raise CaptureError(self.pcap.error(handle))
                if code != 1:
                    raise CaptureError(f"pcap_next_ex 返回未知状态 {code}")
                h = header.contents
                if h.caplen > MAX_PACKET:
                    raise CaptureError("捕获到异常长度的数据包")
                self.count += 1
                p = decode_packet(C.string_at(data,h.caplen),h.ts.tv_sec+h.ts.tv_usec/1e6,h.length,linktype,self.count)
                p.process = resolver.resolve(p)
                try:
                    self.packets.put_nowait(p)
                except queue.Full:
                    self.dropped += 1
            stats = _Stats()
            if api.pcap_stats(handle,C.byref(stats)) == 0:
                self.stats = {"received":stats.received,"kernel_dropped":stats.dropped,
                              "interface_dropped":stats.interface_dropped,"queue_dropped":self.dropped}
                self.events.put(("stats",dict(self.stats)))
        except Exception as exc:
            self.events.put(("error",str(exc)))
        finally:
            if handle:
                api.pcap_close(handle)
            self.events.put(("stopped",{"processed":self.count,"queue_dropped":self.dropped}))

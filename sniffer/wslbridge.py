"""Optional Windows GUI -> existing WSL libpcap bridge, using JSON lines.

No shell interpolation, service installation, authentication, or driver changes.
The bridge captures the selected WSL interface, NOT the Windows host NIC.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

from .capture import CaptureError, CaptureSession, Interface, Pcap
from .protocols import decode_packet


BASE = Path(__file__).resolve().parent.parent


def wsl_path(path):
    path = Path(path).resolve()
    drive = path.drive.rstrip(":").lower()
    if len(drive) != 1:
        raise CaptureError("WSL 桥接需要将源码放在 Windows 本地盘")
    return "/mnt/"+drive+"/"+"/".join(path.parts[1:])


class WslPcap:
    def __init__(self):
        if os.name != "nt":
            raise CaptureError("WSL 桥接仅供 Windows GUI 使用")
        self.creationflags = subprocess.CREATE_NO_WINDOW
        configured = os.environ.get("WIRESCOPE_WSL_DISTRO")
        if configured:
            distributions = [configured]
        else:
            try:
                result = subprocess.run(["wsl.exe","--list","--quiet"],capture_output=True,timeout=8,creationflags=self.creationflags)
            except (OSError,subprocess.TimeoutExpired) as exc:
                raise CaptureError("未发现可用 WSL") from exc
            encoding = "utf-16-le" if b"\0" in result.stdout else "utf-8"
            distributions = [name.strip().lstrip("\ufeff") for name in result.stdout.decode(encoding,"replace").splitlines()
                             if name.strip() and "docker-desktop" not in name]
        self.root = wsl_path(BASE)
        self._interfaces = []
        errors = []
        for distribution in distributions:
            self.distribution = distribution
            try:
                result = subprocess.run(self.command("--list"),capture_output=True,timeout=10,creationflags=self.creationflags)
                if result.returncode:
                    errors.append(result.stderr.decode("utf-8","replace")[-300:])
                    continue
                info = json.loads(result.stdout.decode("utf-8"))
                self.version = f"WSL {distribution} / {info['version']}（抓取 WSL 网络）"
                self._interfaces = [Interface(x["name"],f"WSL {distribution} · {x['description']}",x["loopback"]) for x in info["interfaces"]]
                return
            except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
                errors.append(str(exc))
        raise CaptureError("现有 WSL 中未找到 Python 3.10+ / libpcap。"+(errors[-1] if errors else ""))

    def command(self,*args):
        return ["wsl.exe","--distribution",self.distribution,"--cd",self.root,"--",
                "python3","-u","-m","sniffer.wslbridge",*args]

    def interfaces(self):
        return self._interfaces

    def generate_traffic(self):
        result = subprocess.run(["wsl.exe","--distribution",self.distribution,"--cd",self.root,"--",
                                 "python3","tools/local_traffic.py"],capture_output=True,timeout=20,creationflags=self.creationflags)
        if result.returncode:
            raise CaptureError(result.stderr.decode("utf-8","replace"))
        return result.stdout.decode("utf-8","replace").strip()


class WslCaptureSession:
    def __init__(self,pcap,interface,bpf="",promisc=False):
        self.pcap,self.interface,self.bpf,self.promisc = pcap,interface,bpf,promisc
        self.packets,self.events = queue.Queue(maxsize=2048),queue.SimpleQueue()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run,name="wsl-pcap-bridge",daemon=True)
        self.process,self.stats = None,{}
        self.dropped,self.count = 0,0
        self._lock = threading.Lock()

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        with self._lock:
            if self.process and self.process.poll() is None:
                try:
                    self.process.stdin.write(b"stop\n")
                    self.process.stdin.flush()
                except (OSError,ValueError):
                    pass

    def _run(self):
        process = None
        try:
            command = self.pcap.command("--capture",self.interface.name,"--bpf",self.bpf)
            if self.promisc:
                command.append("--promisc")
            process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                       creationflags=self.pcap.creationflags)
            with self._lock:
                self.process = process
            if self.stop_event.is_set():
                self.stop()
            for line in process.stdout:
                if len(line)>3*1024*1024:
                    raise CaptureError("WSL bridge message 超出上限")
                event = json.loads(line)
                kind,value = event["kind"],event["value"]
                if kind == "packet":
                    self.count += 1
                    raw = base64.b64decode(value["raw"],validate=True)
                    p = decode_packet(raw,value["timestamp"],value["wire_length"],value["linktype"],self.count)
                    p.process = value.get("process","")
                    try:
                        self.packets.put_nowait(p)
                    except queue.Full:
                        self.dropped += 1
                else:
                    if kind == "stats":
                        value["queue_dropped"] = value.get("queue_dropped",0)+self.dropped
                        self.stats = value
                    self.events.put((kind,value))
            code = process.wait(timeout=5)
            if code:
                raise CaptureError(process.stderr.read().decode("utf-8","replace")[-2000:] or f"WSL bridge exited {code}")
        except Exception as exc:
            self.events.put(("error",str(exc)))
        finally:
            if process:
                try:
                    process.stdin.close()  # EOF tells the Linux worker to stop.
                    process.wait(timeout=5)
                except (OSError,ValueError,subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=5)
                for pipe in (process.stdout,process.stderr):
                    pipe.close()
            self.events.put(("stopped",{"processed":self.count,"queue_dropped":self.dropped}))


def default_backend(force="auto"):
    if force == "wsl":
        return WslPcap()
    try:
        return Pcap()
    except CaptureError as native_error:
        if os.name != "nt" or force == "native":
            raise
        try:
            return WslPcap()
        except CaptureError:
            raise native_error


def make_session(backend,interface,bpf="",promisc=False):
    cls = WslCaptureSession if isinstance(backend,WslPcap) else CaptureSession
    return cls(backend,interface,bpf,promisc)


def emit(kind,value):
    print(json.dumps({"kind":kind,"value":value},ensure_ascii=True,separators=(",",":")),flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list",action="store_true")
    parser.add_argument("--capture")
    parser.add_argument("--bpf",default="")
    parser.add_argument("--promisc",action="store_true")
    args = parser.parse_args()
    pcap = Pcap()
    if args.list:
        print(json.dumps({"version":pcap.version,"interfaces":[{"name":i.name,"description":i.description,"loopback":i.loopback}
                         for i in pcap.interfaces()]},ensure_ascii=True))
        return
    session = CaptureSession(pcap,Interface(args.capture,args.capture,args.capture=="lo"),args.bpf,args.promisc)
    def wait_stop():
        sys.stdin.readline()
        session.stop()
    threading.Thread(target=wait_stop,daemon=True).start()
    session.start()
    deadline = time.monotonic()+3600
    try:
        while session.thread.is_alive() or not session.packets.empty():
            if time.monotonic()>deadline:
                session.stop()
            try:
                p = session.packets.get(timeout=0.02)
                emit("packet",{"raw":base64.b64encode(p.raw).decode("ascii"),"timestamp":p.timestamp,
                    "wire_length":p.wire_length,"linktype":p.linktype,"process":p.process})
            except queue.Empty:
                pass
            while not session.events.empty():
                emit(*session.events.get())
        while not session.events.empty():
            emit(*session.events.get())
    finally:
        session.stop()
        session.thread.join(timeout=5)


if __name__ == "__main__":
    main()

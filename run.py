"""Launch GUI, inspect interfaces, or capture a bounded session from CLI."""
import argparse
import json
import queue
import sys
import time

from sniffer.capture import CaptureError, CaptureSession, Pcap
from sniffer.pcapio import MAX_CAPTURE_BYTES, MAX_PACKETS, write_capture
from sniffer.wslbridge import WslPcap, default_backend, make_session


def main():
    parser = argparse.ArgumentParser(description="WireScope — 实验 1A 网络嗅探器")
    parser.add_argument("--demo",action="store_true",help="在 GUI 中打开内置合成样例")
    parser.add_argument("--open",metavar="FILE",help="在 GUI 中打开 PCAP / PCAPNG")
    parser.add_argument("--interfaces",action="store_true",help="列出捕获接口")
    parser.add_argument("--capture",metavar="INTERFACE",help="接口编号、完整名称或 loopback")
    parser.add_argument("--bpf",default="",help="捕获过滤表达式")
    parser.add_argument("--seconds",type=float,default=10,help="命令行捕获时长")
    parser.add_argument("--out",default="capture.pcapng",help="命令行捕获输出文件")
    parser.add_argument("--backend",choices=("auto","native","wsl"),default="auto",help="auto 优先 Npcap，缺失时使用现有 WSL")
    parser.add_argument("--test-traffic",action="store_true",help="在所选后台的本地回环产生受控 HTTP 流量")
    args = parser.parse_args()
    if args.interfaces or args.capture is not None or args.test_traffic:
        try:
            pcap = default_backend(args.backend)
            if args.test_traffic:
                if isinstance(pcap,WslPcap):
                    print(pcap.generate_traffic())
                else:
                    from tools.local_traffic import generate
                    generate()
                    print("本机回环 HTTP 测试完成")
                return 0
            interfaces = pcap.interfaces()
            if args.interfaces:
                print(pcap.version)
                for i,interface in enumerate(interfaces):
                    print(f"{i}: {interface.label}")
                return 0
            if not 0 < args.seconds <= 3600:
                parser.error("--seconds 必须在 0 到 3600 之间")
            chosen = next((item for i,item in enumerate(interfaces) if args.capture in (str(i),item.name) or
                           (args.capture == "loopback" and item.loopback)),None)
            if chosen is None:
                raise CaptureError("未找到接口；请先运行 --interfaces")
            session = make_session(pcap,chosen,args.bpf)
            session.start()
            deadline,packets,size,errors = time.monotonic()+args.seconds,[],0,[]
            try:
                while session.thread.is_alive() or not session.packets.empty():
                    if time.monotonic() >= deadline:
                        session.stop()
                    try:
                        p = session.packets.get(timeout=0.05)
                        if len(packets)<MAX_PACKETS and size+len(p.raw)<=MAX_CAPTURE_BYTES:
                            p.number = len(packets)+1
                            packets.append(p)
                            size += len(p.raw)
                        else:
                            session.stop()
                    except queue.Empty:
                        pass
            except KeyboardInterrupt:
                session.stop()
            finally:
                session.stop()
                session.thread.join(timeout=5)
            while not session.events.empty():
                kind,value = session.events.get()
                if kind == "error":
                    errors.append(value)
            if errors:
                raise CaptureError("; ".join(errors))
            write_capture(args.out,packets)
            print(json.dumps({"packets":len(packets),"bytes":size,"file":args.out,"stats":session.stats},ensure_ascii=False))
            return 0
        except (CaptureError,OSError,ValueError) as exc:
            print(str(exc),file=sys.stderr)
            return 2
    from sniffer.gui import launch
    launch(args.open,args.demo)
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout,"reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())

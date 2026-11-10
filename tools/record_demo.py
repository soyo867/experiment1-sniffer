"""Record a reproducible tour of the real GUI, including live loopback capture.

The tour invokes the same application commands as the buttons. FFmpeg records
the app window, so this is an actual running-program demo, not a slide video.
"""
import argparse
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import time
import tkinter as tk

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from sniffer.gui import SnifferApp
from sniffer.pcapio import read_capture, write_capture
from sniffer.samples import make_demo_packets


def main():
    import imageio_ffmpeg
    base = Path(__file__).resolve().parent.parent
    evidence = base/"evidence"
    evidence.mkdir(exist_ok=True)
    # A DPI-aware recording window prevents GDI from mixing logical and physical pixels.
    if os.name == "nt":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError,OSError):
            pass
    root = tk.Tk()
    root.tk.call("tk","scaling",1.333333)
    app = SnifferApp(root)
    root.title("WireScope Experiment 1A Demo")
    root.geometry("1420x850+25+20")
    root.deiconify()
    root.lift()
    root.attributes("-topmost",True)
    caption_frame = tk.Frame(root,bg="#d9eeed",height=62)
    caption_frame.pack(fill="x",before=app.body.master)
    caption_frame.pack_propagate(False)
    step = tk.Label(caption_frame,text="01 / 12",font=("Segoe UI",14,"bold"),bg="#d9eeed",fg="#087f8c")
    step.pack(side="left",padx=(24,18))
    caption = tk.Label(caption_frame,text="实验 1A：真实抓包、协议分析与 TCP 流追踪",font=("Microsoft YaHei UI",13,"bold"),bg="#d9eeed",fg="#142b45")
    caption.pack(side="left")
    root.update()
    errors = []
    root.report_callback_exception = lambda *args:errors.append(str(args))
    log = (evidence/"video_ffmpeg.log").open("w",encoding="utf-8")
    command = [imageio_ffmpeg.get_ffmpeg_exe(),"-hide_banner","-y","-f","gdigrab","-framerate","12",
               "-draw_mouse","0","-i","title=WireScope Experiment 1A Demo","-vf","scale=1440:-2",
               "-c:v","libx264","-preset","veryfast","-crf","20","-pix_fmt","yuv420p","-movflags","+faststart",
               str(evidence/"ex1A_play.mp4")]
    process = None
    lead_in = 30  # Allow the desktop to foreground the recording window before capture.
    def begin_recording():
        nonlocal process
        root.lift()
        root.focus_force()
        root.update_idletasks()
        process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW,
                                   env={**os.environ,"__COMPAT_LAYER":"HIGHDPIAWARE"})
    root.after(lead_in*1000,begin_recording)
    def banner(n,text):
        step.configure(text=f"{n:02d} / 12")
        caption.configure(text=text)
    def at(seconds,callback):
        root.after(int((lead_in+seconds)*1000),callback)
    def select_packet(number,focus=None):
        app.packet_tree.selection_set(str(number))
        app.packet_tree.see(str(number))
        app.select_packet()
        if focus:
            for item in app.detail_tree.get_children():
                name = app.detail_tree.item(item,"text")
                app.detail_tree.item(item,open=name == focus)
                if name == focus:
                    app.detail_tree.selection_set(item)
                    app.detail_tree.see(item)
    def start():
        banner(2,"真实捕获：WSL 回环网卡 + BPF tcp port 18080")
        app.bpf_var.set("tcp port 18080")
        app.start_capture()
    def generate():
        banner(3,"发送 8 次本地 HTTP 请求，观察数据包实时进入列表")
        app.generate_traffic()
    def stop():
        app.stop_capture()
        banner(4,"停止捕获；查看 HTTP 请求、响应与原始字节")
    def http():
        app.set_filter("http")
        matches = [p for p in app.packets if p.protocol == "HTTP"]
        if not matches:
            raise RuntimeError("Demo failed: no real HTTP packets")
        select_packet(matches[0].number,"HTTP")
        write_capture(evidence/"demo_live.pcapng",app.packets)
    def follow():
        banner(5,"按双向 IP + Port 追踪 TCP 流，重组请求字节")
        app.follow_selected()
        app.flow_tabs.select(0)
    def response():
        banner(6,"同一长连接中的响应；逐方向展示应用层载荷")
        app.flow_tabs.select(1)
    def timeline():
        banner(7,"连接时序：握手、请求/响应与关闭；按时间标出方向")
        app.flow_tabs.select(2)
    def reopen():
        banner(8,"将真实捕获保存为 PCAPNG，再从文件重新打开")
        app.set_filter("")
        app.load_packets(read_capture(evidence/"demo_live.pcapng"),"demo_live.pcapng · 真实回环捕获回读")
    def ipv6():
        banner(9,"合成覆盖样例：IPv6 / ICMPv6 / 扩展头协议筛选")
        app.load_packets(make_demo_packets(),"内置合成样例 · 非实抓流量")
        app.set_filter("ipv6")
        select_packet(17,"ICMPv6")
    def dns():
        banner(10,"DNS：压缩域名解析、查询与响应、资源记录")
        app.set_filter("dns")
        select_packet(3,"DNS")
    def tls():
        banner(11,"TLS：解析 ClientHello 与 SNI；加密内容保持原始字节")
        app.set_filter("tls")
        select_packet(20,"TLS")
    def stats():
        banner(12,"统计、文件导出与测试证据随源码和实验报告一同提交")
        app.notebook.select(app.stats_tab)
        app.draw_stats()
    def finish():
        if app.session:
            app.stop_capture()
        try:
            process.stdin.write(b"q\n")
            process.stdin.flush()
            process.wait(timeout=15)
        finally:
            log.close()
            root.destroy()
        if errors or process.returncode:
            raise RuntimeError(f"Demo errors: {errors}; ffmpeg exit={process.returncode}")
    at(6,start)
    at(10,generate)
    at(20,stop)
    at(23,http)
    at(32,follow)
    at(41,response)
    at(49,timeline)
    at(59,reopen)
    at(68,ipv6)
    at(78,dns)
    at(88,tls)
    at(98,stats)
    at(108,finish)
    root.mainloop()
    print("Demo recording complete:",evidence/"ex1A_play.mp4")


if __name__ == "__main__":
    main()

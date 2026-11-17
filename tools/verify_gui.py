"""Exercise actual Tk widgets, file round trips, and live capture from the GUI."""
import json
from pathlib import Path
import sys
import tempfile
import time
import tkinter as tk
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from sniffer.gui import SnifferApp
from sniffer.pcapio import read_capture
from sniffer.samples import make_demo_packets


def run():
    root = tk.Tk()
    app = SnifferApp(root)
    root.withdraw()
    callback_errors = []
    root.report_callback_exception = lambda *args:callback_errors.append(str(args))
    def pump(seconds):
        deadline = time.monotonic()+seconds
        while time.monotonic()<deadline:
            root.update()
            time.sleep(0.01)
    checks = []
    try:
        app.load_packets(make_demo_packets(),"GUI 自动测试合成样例")
        pump(0.1)
        assert len(app.packet_tree.get_children()) == 24
        checks.append("load synthetic fixture in packet table")
        app.set_filter("http")
        pump(0.1)
        assert len(app.packet_tree.get_children()) == 4
        checks.append("HTTP navigation filter")
        app.filter_var.set("tcp and")
        assert not app.apply_filter()
        assert len(app.packet_tree.get_children()) == 4
        checks.append("invalid filter preserves previous result")
        app.set_filter("tcp and port == 8080")
        pump(0.1)
        assert len(app.packet_tree.get_children()) == 11
        app.packet_tree.selection_set("8")
        pump(0.1)
        assert app.detail_tree.get_children()
        assert "0000" in app.hex_text.get("1.0","end")
        app.follow_selected()
        pump(0.1)
        assert "GET /experiment/1a" in app.flow_texts[0].get("1.0","end")
        assert "reassembly passed" in app.flow_texts[1].get("1.0","end")
        assert app.flow_canvas.find_all()
        checks.append("packet selection, details, hex, flow reassembly and sequence chart")
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory)/"filtered.pcapng")
            with patch("sniffer.gui.filedialog.asksaveasfilename",return_value=output):
                app.save_file(True)
            assert len(read_capture(output)) == 11
            app.load_path(output)
            for _ in range(100):
                pump(0.03)
                if not app.loading:
                    break
            assert len(app.packets) == 11
        checks.append("filtered export and asynchronous reopen")
        app.set_filter("")
        with patch("sniffer.gui.messagebox.askyesno",return_value=True):
            app.bpf_var.set("tcp port 18080")
            app.start_capture()
        for _ in range(200):
            pump(0.03)
            if "LIVE" in app.mode.cget("text"):
                break
        assert app.session is not None and "LIVE" in app.mode.cget("text")
        app.generate_traffic()
        pump(5.5)
        app.stop_capture()
        for _ in range(200):
            pump(0.03)
            if app.session is None:
                break
        assert app.session is None
        assert sum(p.protocol == "HTTP" for p in app.packets)>=10
        assert "STOPPED" in app.mode.cget("text")
        checks.append("GUI live start, local test traffic, packet delivery, stop")
        app.notebook.select(app.stats_tab)
        pump(0.1)
        assert app.stats_canvas.find_all()
        checks.append("statistics visualization")
        live_packets = len(app.packets)
        evidence = Path(__file__).resolve().parent.parent/'evidence'
        owners = json.loads((evidence/'process_capture_owners.json').read_text(encoding='utf-8'))
        packets = read_capture(evidence/'process_capture.pcapng')
        for packet in packets:
            packet.process = owners.get(str(packet.number),'')
        app.load_packets(packets,'实抓进程证据回放（PID 来自同次捕获 sidecar）')
        app.notebook.select(app.process_tab)
        app.refresh_processes()
        pump(0.1)
        ids = app.process_tree.get_children()
        assert len(ids) == 2, ids
        for flow_id in ids:
            app.process_tree.selection_set(flow_id)
            app.follow_process_flow()
            pump(0.1)
            assert app.current_flow.id == int(flow_id)
            assert 'GET /process-stream-' in ''.join(t.get('1.0','end') for t in app.flow_texts)
        checks.append('process evidence replay: same PID lists both TCP flows and opens each stream')
        assert not callback_errors,callback_errors
        result = {"result":"PASS","checks":checks,"live_packets":live_packets,"process_flows":len(ids),"tk_callback_errors":callback_errors}
        (Path(__file__).resolve().parent.parent/"evidence/gui_verification.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
        print(json.dumps(result,ensure_ascii=False,indent=2))
    finally:
        if app.session:
            app.session.stop()
            app.session.thread.join(timeout=10)
        root.destroy()


if __name__ == "__main__":
    run()

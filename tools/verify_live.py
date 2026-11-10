"""Run a real libpcap/Npcap integration test using controlled loopback HTTP."""
from collections import Counter
import json
from pathlib import Path
import queue
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from sniffer.capture import CaptureError
from sniffer.pcapio import read_capture, write_capture
from sniffer.streams import FlowIndex
from sniffer.wslbridge import WslPcap, default_backend, make_session
from tools.local_traffic import generate


def started(session):
    deadline = time.monotonic()+20
    while time.monotonic()<deadline:
        try:
            kind,value = session.events.get(timeout=0.2)
        except queue.Empty:
            continue
        if kind == "error":
            raise RuntimeError(value)
        if kind == "started":
            return value
    session.stop()
    raise RuntimeError("Capture did not start")


def run(output):
    output = Path(output)
    output.mkdir(parents=True,exist_ok=True)
    backend = default_backend()
    interface = next(i for i in backend.interfaces() if i.loopback)
    session = make_session(backend,interface,"tcp port 18080")
    session.start()
    started(session)
    try:
        if isinstance(backend,WslPcap):
            backend.generate_traffic()
        else:
            generate(count=8)
        time.sleep(0.25)
    finally:
        before = time.monotonic()
        session.stop()
        session.thread.join(timeout=10)
    stop_latency = time.monotonic()-before
    assert not session.thread.is_alive(),"Capture thread failed to stop"
    packets = []
    while not session.packets.empty():
        p = session.packets.get()
        p.number = len(packets)+1
        packets.append(p)
    errors = []
    while not session.events.empty():
        kind,value = session.events.get()
        if kind == "error":
            errors.append(value)
    assert not errors,errors
    assert packets,"No live packets received"
    assert all(p.transport == "TCP" and 18080 in (p.sport,p.dport) for p in packets),"BPF allowed unexpected traffic"
    assert all(p.src == p.dst == "127.0.0.1" for p in packets),"Unexpected capture scope"
    requests = [p for p in packets if p.protocol == "HTTP" and p.info.startswith("GET ")]
    responses = [p for p in packets if p.protocol == "HTTP" and p.info.startswith("HTTP/1.1 200")]
    assert len(requests) == len(responses) == 8,(len(requests),len(responses))
    assert not any(p.warnings for p in packets),"Malformed packet in controlled traffic"
    index = FlowIndex()
    for p in packets:
        index.add(p)
    assert len(index.flows) == 1,len(index.flows)
    flow = index.flows[0]
    assert b"real loopback packet capture" in flow.assembled(1).data
    assert not flow.assembled(0).gaps and not flow.assembled(1).gaps
    write_capture(output/"live_loopback.pcapng",packets)
    write_capture(output/"live_loopback.pcap",packets)
    assert [p.raw for p in read_capture(output/"live_loopback.pcapng")] == [p.raw for p in packets]
    (output/"live_tcp_stream.txt").write_text(flow.export_text(),encoding="utf-8")
    idle = make_session(backend,interface,"tcp port 18081")
    idle.start()
    started(idle)
    time.sleep(0.1)
    before = time.monotonic()
    idle.stop()
    idle.thread.join(timeout=5)
    idle_latency = time.monotonic()-before
    assert not idle.thread.is_alive(),"Idle capture failed to stop"
    invalid = make_session(backend,interface,"this is invalid bpf !!!")
    invalid.start()
    invalid.thread.join(timeout=10)
    assert not invalid.thread.is_alive(),"Bad BPF did not fail promptly"
    invalid_errors = []
    while not invalid.events.empty():
        kind,value = invalid.events.get()
        if kind == "error":
            invalid_errors.append(value)
    assert invalid_errors,"Invalid BPF silently accepted"
    evidence = {"result":"PASS","backend":backend.version,"interface":interface.name,
                "capture_scope":"WSL loopback" if isinstance(backend,WslPcap) else "native loopback",
                "packet_count":len(packets),"protocol_counts":dict(Counter(p.protocol for p in packets)),
                "http_requests":len(requests),"http_responses":len(responses),"tcp_flows":len(index.flows),
                "stop_latency_seconds":round(stop_latency,4),"idle_stop_latency_seconds":round(idle_latency,4),
                "invalid_bpf_rejected":True,"pcap_roundtrip":True,"statistics":session.stats,
                "process_associated_packets":sum(bool(p.process) for p in packets)}
    (output/"live_verification.json").write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(evidence,ensure_ascii=False,indent=2))
    return evidence


if __name__ == "__main__":
    if hasattr(sys.stdout,"reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    run(Path(__file__).resolve().parent.parent/"evidence")

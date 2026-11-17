"""Real Linux/WSL proof: two connections from the same process are traced."""
from pathlib import Path
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from sniffer.capture import Pcap,CaptureSession
from sniffer.streams import FlowIndex
from sniffer.pcapio import write_capture


def run():
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen()
    port=listener.getsockname()[1]
    accepted=[]; stop=threading.Event()
    def accept():
        while len(accepted)<2:
            peer,_=listener.accept(); accepted.append(peer)
    thread=threading.Thread(target=accept); thread.start()
    pcap=Pcap(); interface=next(i for i in pcap.interfaces() if i.loopback)
    session=CaptureSession(pcap,interface,f'tcp port {port}')
    session.start()
    deadline=time.monotonic()+5
    while True:
        kind,value=session.events.get(timeout=5)
        if kind=='error': raise RuntimeError(value)
        if kind=='started': break
        if time.monotonic()>deadline: raise RuntimeError('startup timeout')
    clients=[]
    try:
        clients=[socket.create_connection(('127.0.0.1',port)) for _ in range(2)]
        thread.join(3)
        time.sleep(1.1)  # Socket ownership snapshot sees both established streams.
        for n,client in enumerate(clients):
            client.sendall(f'GET /process-stream-{n} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
            accepted[n].recv(4096)
            accepted[n].sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
            client.recv(4096)
        time.sleep(0.15)
    finally:
        for sock in clients+accepted: sock.close()
        listener.close(); session.stop(); session.thread.join(5)
    packets=[]; index=FlowIndex()
    while not session.packets.empty():
        p=session.packets.get(); p.number=len(packets)+1; packets.append(p); index.add(p)
    label=f'({os.getpid()})'
    flows=[f for f in index.flows if any(label in p.process for p in f.packets)]
    assert len(flows)==2,[(f.id,[p.process for p in f.packets]) for f in index.flows]
    result={'result':'PASS','pid':os.getpid(),'flow_count':len(flows),'associated_packets':sum(label in p.process for p in packets),
            'backend':pcap.version,'method':'Linux /proc exact TCP tuple and socket inode ownership',
            'flows':[{'id':f.id,'a':list(f.a),'b':list(f.b),'packets':len(f.packets)} for f in flows]}
    evidence=Path(__file__).resolve().parent.parent/'evidence'
    (evidence/'process_verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    # Standard PCAP does not preserve PID. Sidecar preserves lab evidence for GUI inspection.
    write_capture(evidence/'process_capture.pcapng',packets)
    (evidence/'process_capture_owners.json').write_text(json.dumps({str(p.number):p.process for p in packets},ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__': run()

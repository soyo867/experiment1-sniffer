"""Deterministic, synthetic fixtures. TEST-NET addresses; no network transmission."""
import ipaddress
import struct

from .pcapio import write_capture
from .protocols import decode_packet


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!"+"H"*(len(data)//2),data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload, typ=0x0800, vlan=None):
    header = bytes.fromhex("020000000002020000000001")
    if vlan is not None:
        return header+struct.pack("!HHH",0x8100,vlan,typ)+payload
    return header+struct.pack("!H",typ)+payload


def ipv4(payload, proto=6, src="192.0.2.10", dst="198.51.100.20", ident=1, fragment=0):
    head = struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(payload),ident,fragment,64,proto,0,
                       ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed)
    head = head[:10]+struct.pack("!H",checksum(head))+head[12:]
    return head+payload


def ipv6(payload, proto=17, src="2001:db8::10", dst="2001:db8::20"):
    return struct.pack("!IHBB16s16s",0x60000000,len(payload),proto,64,
                       ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed)+payload


def transport_checksum(segment, proto, src, dst):
    a,b = ipaddress.ip_address(src),ipaddress.ip_address(dst)
    pseudo = a.packed+b.packed
    pseudo += struct.pack("!BBH",0,proto,len(segment)) if a.version == 4 else struct.pack("!I3xB",len(segment),proto)
    return checksum(pseudo+segment)


def tcp(payload=b"", sport=51000, dport=8080, seq=1000, ack=9000, flags=0x18,
        src="192.0.2.10", dst="198.51.100.20"):
    segment = struct.pack("!HHIIBBHHH",sport,dport,seq,ack,0x50,flags,64240,0,0)+payload
    return segment[:16]+struct.pack("!H",transport_checksum(segment,6,src,dst))+segment[18:]


def udp(payload, sport=54000, dport=53, src="192.0.2.10", dst="198.51.100.20"):
    segment = struct.pack("!HHHH",sport,dport,8+len(payload),0)+payload
    check = transport_checksum(segment,17,src,dst) or 0xFFFF
    return segment[:6]+struct.pack("!H",check)+payload


def dns_query(ident=0x1234):
    return struct.pack("!6H",ident,0x0100,1,0,0,0)+b"\x03lab\x07example\0"+struct.pack("!HH",1,1)


def tls_hello(host=b"lab.example"):
    name = b"\0"+struct.pack("!H",len(host))+host
    sni = struct.pack("!H",len(name))+name
    extension = struct.pack("!HH",0,len(sni))+sni
    hello = b"\x03\x03"+bytes(range(32))+b"\0\0\x02\x13\x01\x01\0"+struct.pack("!H",len(extension))+extension
    handshake = b"\x01"+len(hello).to_bytes(3,"big")+hello
    return b"\x16\x03\x01"+struct.pack("!H",len(handshake))+handshake


def make_demo_packets():
    raws = []
    client, server = "192.0.2.10","198.51.100.20"
    def ct(payload=b"",seq=1000,ack=9000,flags=0x18,reverse=False,port=8080):
        src,dst,sport,dport = (server,client,port,51000) if reverse else (client,server,51000,port)
        raws.append(ethernet(ipv4(tcp(payload,sport,dport,seq,ack,flags,src,dst),6,src,dst)))
    # ARP request.
    arp = struct.pack("!HHBBH",1,0x0800,6,4,1)+bytes.fromhex("020000000001")+ipaddress.ip_address(client).packed+b"\0"*6+ipaddress.ip_address(server).packed
    raws.append(ethernet(arp,0x0806))
    query = dns_query()
    raws.append(ethernet(ipv4(udp(query),17)))
    response = struct.pack("!6H",0x1234,0x8180,1,1,0,0)+query[12:]+b"\xc0\x0c"+struct.pack("!HHIH",1,1,60,4)+ipaddress.ip_address(server).packed
    raws.append(ethernet(ipv4(udp(response,53,54000,server,client),17,server,client)))
    ct(flags=2,ack=0)
    ct(seq=9000,ack=1001,flags=0x12,reverse=True)
    ct(seq=1001,ack=9001,flags=0x10)
    request = b"GET /experiment/1a HTTP/1.1\r\nHost: lab.example\r\nUser-Agent: WireScope-Lab\r\nConnection: keep-alive\r\n\r\n"
    cut = 39
    ct(request[cut:],seq=1001+cut,ack=9001)  # out of order
    ct(request[:cut],seq=1001,ack=9001)
    ct(request[:cut],seq=1001,ack=9001)  # retransmission
    body = b"Experiment 1A: packet capture and TCP stream reassembly passed.\n"
    answer = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body
    ct(answer[:85],seq=9001,ack=1001+len(request),reverse=True)
    ct(answer[85:],seq=9086,ack=1001+len(request),reverse=True)
    ct(seq=1001+len(request),ack=9001+len(answer),flags=0x11)
    ct(seq=9001+len(answer),ack=1002+len(request),flags=0x11,reverse=True)
    ct(seq=1002+len(request),ack=9002+len(answer),flags=0x10)
    # Content-based HTTP recognition on a nonstandard port.
    ct(b"GET /health HTTP/1.1\r\nHost: lab.example\r\n\r\n",seq=1,ack=1,port=18080)
    # IPv6 DNS / ICMPv6, ICMPv4, VLAN UDP.
    src6,dst6 = "2001:db8::10","2001:db8::20"
    raws.append(ethernet(ipv6(udp(query,54001,53,src6,dst6)),0x86DD))
    icmp6 = struct.pack("!BBHHH",128,0,0,9,1)+b"WireScope IPv6"
    icmp6 = icmp6[:2]+struct.pack("!H",transport_checksum(icmp6,58,src6,dst6))+icmp6[4:]
    raws.append(ethernet(ipv6(icmp6,58),0x86DD))
    icmp = struct.pack("!BBHHH",8,0,0,7,1)+b"WireScope IPv4"
    icmp = icmp[:2]+struct.pack("!H",checksum(icmp))+icmp[4:]
    raws.append(ethernet(ipv4(icmp,1)))
    raws.append(ethernet(ipv4(udp(b"VLAN 42 lab datagram",54002,9999),17),vlan=42))
    # TLS metadata only: the bytes below are synthetic test records.
    ct(tls_hello(),seq=2001,ack=1,port=443)
    ct(b"\x17\x03\x03\x00\x10"+bytes(range(16)),seq=2001+len(tls_hello()),ack=1,port=443)
    # IPv6 hop-by-hop extension carrying UDP.
    ext = bytes([17,0])+b"\0"*6
    raws.append(ethernet(ipv6(ext+udp(b"IPv6 extension test",54003,9999,src6,dst6),0),0x86DD))
    # A fragmented IPv4 datagram is explicitly left unreassembled.
    raws.append(ethernet(ipv4(b"fragment"*2,17,fragment=0x2000)))
    # Malformed fixtures for diagnostics; retained byte-for-byte on export.
    raws.append(ethernet(ipv4(tcp(b"truncated")))[:38])
    return [decode_packet(raw,1794268800+i*0.037,len(raw),1,i+1) for i,raw in enumerate(raws)]


def save_demo(path):
    packets = make_demo_packets()
    write_capture(path,packets)
    return packets

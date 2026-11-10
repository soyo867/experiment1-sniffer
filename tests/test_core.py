import ctypes as C
from dataclasses import replace
import random
import struct
import tempfile
from pathlib import Path
import unittest

from sniffer.filters import FilterError, compile_filter
from sniffer.model import Packet
from sniffer.pcapio import CaptureFileError, read_capture, write_capture
from sniffer.protocols import DecodeError, decode_packet, dns_name, parse_http, parse_tls
from sniffer.samples import dns_query, ethernet, ipv4, ipv6, make_demo_packets, tcp, tls_hello, udp
from sniffer.streams import FlowIndex, reassemble


def packet(seq, data=b"", flags=0x18):
    return Packet(1,0,b"",0,transport="TCP",src="192.0.2.1",dst="192.0.2.2",ip_version=4,
                  sport=1234,dport=80,seq=seq,flags=flags,payload=data)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.packets = make_demo_packets()

    def test_protocol_coverage(self):
        self.assertTrue({"ARP","TCP","UDP","HTTP","DNS","TLS","ICMP","ICMPv6"} <= {p.protocol for p in self.packets})

    def test_http_nonstandard_port(self):
        p = next(p for p in self.packets if p.dport == 18080)
        self.assertEqual(p.protocol,"HTTP")
        self.assertIn("/health",p.info)

    def test_port_80_is_not_enough(self):
        p = decode_packet(ethernet(ipv4(tcp(b"this is not HTTP",dport=80))))
        self.assertEqual(p.protocol,"TCP")

    def test_tls_sni(self):
        fields,info = parse_tls(tls_hello())
        self.assertEqual(fields["Server Name (SNI)"],"lab.example")
        self.assertIn("ClientHello",info)

    def test_incomplete_tls(self):
        fields,info = parse_tls(tls_hello()[:8])
        self.assertFalse(fields["Record complete"])
        self.assertNotIn("SNI",fields)

    def test_dns_compressed_answer(self):
        p = self.packets[2]
        self.assertEqual(p.protocol,"DNS")
        self.assertIn("198.51.100.20",p.info)

    def test_dns_pointer_loop(self):
        with self.assertRaises(DecodeError):
            dns_name(b"\xc0\x00",0)

    def test_dns_pointer_out_of_bounds(self):
        with self.assertRaises(DecodeError):
            dns_name(b"\xc0\xff",0)

    def test_ipv6_extension(self):
        p = self.packets[21]
        self.assertEqual(p.ip_version,6)
        self.assertEqual(p.protocol,"UDP")
        self.assertIn("ipv6 extension",p.protocols)

    def test_vlan(self):
        p = self.packets[18]
        self.assertEqual(next(l for l in p.layers if l.name == "VLAN").fields["ID"],42)
        self.assertEqual(p.dport,9999)

    def test_ipv4_fragment_not_transport(self):
        p = self.packets[22]
        self.assertEqual(p.transport,"")
        self.assertIn("fragment",p.info)

    def test_ipv6_fragment_not_transport(self):
        fragment = struct.pack("!BBHI",6,0,9,123)+tcp(b"fragment")
        p = decode_packet(ethernet(ipv6(fragment,44),0x86DD))
        self.assertEqual(p.transport,"")
        self.assertIn("fragment",p.info)

    def test_loopback_ipv4(self):
        raw = struct.pack("<I",2)+ipv4(tcp(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertEqual(decode_packet(raw,linktype=0).protocol,"HTTP")

    def test_loopback_ipv6(self):
        raw = struct.pack("<I",23)+ipv6(b"\x80\0\0\0\0\x01\0\x01",58)
        self.assertEqual(decode_packet(raw,linktype=0).protocol,"ICMPv6")

    def test_raw_and_sll(self):
        raw = ipv4(tcp(b"hello"))
        self.assertEqual(decode_packet(raw,linktype=101).transport,"TCP")
        self.assertEqual(decode_packet(b"\0"*14+b"\x08\0"+raw,linktype=113).transport,"TCP")
        self.assertEqual(decode_packet(b"\x08\0"+b"\0"*18+raw,linktype=276).transport,"TCP")

    def test_unknown_linktype(self):
        self.assertIn("Unsupported",decode_packet(b"abc",linktype=999).info)

    def test_truncated_packet_diagnostics(self):
        self.assertTrue(self.packets[-1].warnings)

    def test_udp_invalid_length(self):
        p = decode_packet(ethernet(ipv4(struct.pack("!4H",1000,1001,7,0),17)))
        self.assertTrue(p.warnings)

    def test_tcp_invalid_data_offset(self):
        data = bytearray(tcp())
        data[12] = 0x10
        self.assertTrue(decode_packet(ethernet(ipv4(data))).warnings)

    def test_ipv4_options_offset(self):
        payload = tcp(b"GET / HTTP/1.1\r\n\r\n")
        ip = bytearray(ipv4(b"\0"*4+payload))
        ip[0] = 0x46
        self.assertEqual(decode_packet(ethernet(ip)).protocol,"HTTP")

    def test_all_truncation_offsets(self):
        for p in self.packets:
            for end in range(len(p.raw)):
                with self.subTest(packet=p.number,end=end):
                    result = decode_packet(p.raw[:end],wire_length=len(p.raw))
                    self.assertEqual(result.raw,p.raw[:end])

    def test_seeded_random_frames(self):
        rng = random.Random(20261110)
        for i in range(3000):
            raw = rng.randbytes(rng.randrange(257))
            p = decode_packet(raw,linktype=rng.choice([0,1,101,108,113,276,999]))
            self.assertEqual(p.raw,raw)


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.packets = make_demo_packets()
        index = FlowIndex()
        for p in self.packets:
            index.add(p)

    def match(self,expr):
        return [p for p in self.packets if compile_filter(expr)(p)]

    def test_empty(self):
        self.assertEqual(len(self.match("  ")),24)

    def test_layer_membership(self):
        self.assertTrue(all(p.transport == "TCP" for p in self.match("tcp")))
        self.assertTrue(any(p.protocol == "HTTP" for p in self.match("tcp")))

    def test_precedence(self):
        self.assertEqual([p.number for p in self.match("http or udp and dns")],
                         [p.number for p in self.packets if p.protocol == "HTTP" or (p.transport == "UDP" and p.protocol == "DNS")])

    def test_parentheses_and_not(self):
        self.assertEqual(len(self.match("(ipv6 or icmp) and not dns")),3)

    def test_filter_by_endpoint(self):
        self.assertEqual(len(self.match("tcp and port == 8080")),11)
        self.assertEqual(len(self.match('info contains "GET"')),3)

    def test_inequality_both_endpoints(self):
        matches = self.match("port != 8080")
        self.assertTrue(matches)
        self.assertTrue(all(p.sport != 8080 and p.dport != 8080 for p in matches))
        self.assertTrue(all(p.sport is not None for p in matches))

    def test_ipv6_address_normalization(self):
        self.assertEqual(len(self.match("ip.src == 2001:0db8:0:0:0:0:0:10")),3)

    def test_stream_filter(self):
        self.assertEqual(len(self.match("tcp.stream == 0")),11)

    def test_bad_filters(self):
        for expr in ["tcp and", "tcp udp", "port == nope", "banana", "(tcp", "tcp)","tcp & udp", "length contains 4", "ip.src == nope", "__import__('os')", "info > 5"]:
            with self.subTest(expr=expr),self.assertRaises(FilterError):
                compile_filter(expr)


class StreamTests(unittest.TestCase):
    def test_out_of_order_retransmission(self):
        packets = [packet(100,flags=2),packet(104,b"def"),packet(101,b"abc"),packet(101,b"abc")]
        result = reassemble(packets)
        self.assertEqual(result.data,b"abcdef")
        self.assertEqual(result.overlap_bytes,3)
        self.assertEqual(result.conflict_bytes,0)

    def test_conflicting_overlap_first_seen_wins(self):
        result = reassemble([packet(100,flags=2),packet(101,b"abcdef"),packet(103,b"XXghij")])
        self.assertEqual(result.data,b"abcdefij")
        self.assertEqual(result.conflict_bytes,4)

    def test_gap_not_silently_joined(self):
        result = reassemble([packet(100,flags=2),packet(101,b"abc"),packet(110,b"later")])
        self.assertEqual(result.data,b"abc")
        self.assertEqual(result.gaps,[(3,9)])
        self.assertIn("缺失 6",result.text())

    def test_leading_gap(self):
        result = reassemble([packet(100,flags=2),packet(103,b"cde")])
        self.assertEqual(result.data,b"")
        self.assertEqual(result.gaps,[(0,2)])

    def test_sequence_wrap(self):
        result = reassemble([packet(0xFFFFFFFD,flags=2),packet(1,b"def"),packet(0xFFFFFFFE,b"abc")])
        self.assertEqual(result.data,b"abcdef")

    def test_midstream(self):
        result = reassemble([packet(105,b"world"),packet(100,b"hello")])
        self.assertEqual(result.data,b"helloworld")
        self.assertTrue(result.missing_prefix)

    def test_syn_consumes_one_sequence(self):
        result = reassemble([packet(100,b"first",flags=2),packet(106,b"second")])
        self.assertEqual(result.data,b"firstsecond")

    def test_bidirectional_connection(self):
        index = FlowIndex()
        a = packet(100,flags=2)
        b = replace(a,src=a.dst,dst=a.src,sport=80,dport=1234,seq=200,flags=0x12)
        index.add(a)
        index.add(b)
        self.assertEqual(a.flow_id,b.flow_id)
        self.assertEqual(index.flows[0].direction(b),1)

    def test_tuple_reuse_new_syn(self):
        index = FlowIndex()
        for p in [packet(100,flags=2),packet(100,flags=2),packet(9000,flags=2)]:
            index.add(p)
        self.assertEqual(len(index.flows),2)

    def test_fin_then_same_isn(self):
        index = FlowIndex()
        a = packet(100,flags=2)
        index.add(a)
        index.add(packet(101,flags=0x11))
        index.add(replace(packet(201,flags=0x11),src=a.dst,dst=a.src,sport=80,dport=1234))
        index.add(packet(100,flags=2))
        self.assertEqual(len(index.flows),2)

    def test_demo_http_reassembled(self):
        index = FlowIndex()
        for p in make_demo_packets():
            index.add(p)
        self.assertTrue(index.flows[0].assembled(0).data.startswith(b"GET /experiment/1a"))
        self.assertIn(b"reassembly passed",index.flows[0].assembled(1).data)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.packets = make_demo_packets()

    def test_pcap_roundtrip(self):
        path = self.root/"中文.pcap"
        write_capture(path,self.packets)
        actual = read_capture(path)
        self.assertEqual([p.raw for p in actual],[p.raw for p in self.packets])
        self.assertEqual([p.protocol for p in actual],[p.protocol for p in self.packets])
        self.assertAlmostEqual(actual[4].timestamp,self.packets[4].timestamp,places=5)

    def test_pcapng_roundtrip(self):
        path = self.root/"中文.pcapng"
        write_capture(path,self.packets)
        self.assertEqual([p.raw for p in read_capture(path)],[p.raw for p in self.packets])

    def test_mixed_interfaces(self):
        p = decode_packet(ipv4(tcp()),linktype=101,number=25)
        path = self.root/"mixed.pcapng"
        write_capture(path,self.packets+[p])
        self.assertEqual(read_capture(path)[-1].linktype,101)
        with self.assertRaises(CaptureFileError):
            write_capture(self.root/"bad.pcap",self.packets+[p])

    def test_empty_capture(self):
        for ext in ("pcap","pcapng"):
            path = self.root/ext
            write_capture(path,[])
            self.assertEqual(read_capture(path),[])

    def test_big_endian_nanoseconds(self):
        path = self.root/"nano.pcap"
        raw = self.packets[0].raw
        path.write_bytes(struct.pack(">IHHIIII",0xA1B23C4D,2,4,0,0,65535,1)+struct.pack(">IIII",100,123456789,len(raw),len(raw))+raw)
        self.assertAlmostEqual(read_capture(path)[0].timestamp,100.123456789)

    def test_ng_multiple_sections(self):
        path = self.root/"multi.pcapng"
        write_capture(path,self.packets)
        data = path.read_bytes()
        path.write_bytes(data+data)
        self.assertEqual(len(read_capture(path)),48)

    def test_bad_ng_tail(self):
        path = self.root/"bad.pcapng"
        write_capture(path,self.packets)
        path.write_bytes(path.read_bytes()[:-4]+b"\0"*4)
        with self.assertRaises(CaptureFileError):
            read_capture(path)

    def test_oversized_length_no_allocation(self):
        path = self.root/"oversize.pcap"
        path.write_bytes(struct.pack("<IHHIIII",0xA1B2C3D4,2,4,0,0,65535,1)+struct.pack("<IIII",1,1,0xFFFFFFFF,0xFFFFFFFF))
        with self.assertRaises(CaptureFileError):
            read_capture(path)

    def test_truncated_record(self):
        path = self.root/"truncated.pcap"
        write_capture(path,self.packets)
        path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaises(CaptureFileError):
            read_capture(path)

    def test_unknown_format(self):
        path = self.root/"bad"
        path.write_bytes(b"not a capture")
        with self.assertRaises(CaptureFileError):
            read_capture(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)

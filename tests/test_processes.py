"""Socket ownership parsing, race handling and exact packet attribution."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sniffer.capture import ProcessResolver
from sniffer.processes import linux_socket_snapshot, proc_endpoint


class EndpointTests(unittest.TestCase):
    def test_ipv4_little_endian(self):
        with patch('sniffer.processes.sys.byteorder', 'little'):
            self.assertEqual(proc_endpoint('0100007F:C350'), ('127.0.0.1', 50000))

    def test_ipv6_word_order(self):
        with patch('sniffer.processes.sys.byteorder', 'little'):
            self.assertEqual(proc_endpoint('00000000000000000000000001000000:01BB'), ('::1', 443))
            self.assertEqual(proc_endpoint('0000000000000000FFFF00000100007F:0050'), ('::ffff:127.0.0.1', 80))

    def test_big_endian(self):
        with patch('sniffer.processes.sys.byteorder', 'big'):
            self.assertEqual(proc_endpoint('C0000201:0000'), ('192.0.2.1', 0))
            self.assertEqual(proc_endpoint('20010DB8000000000000000000000001:FFFF'), ('2001:db8::1', 65535))

    def test_malformed_endpoint(self):
        for value in ('bad', 'XYZ:0010', '0100:0050', '0100007F:10000', '0100007F:-1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                proc_endpoint(value)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name)
        (self.proc/'net').mkdir()
        self.links = {}

    def table(self, name, rows):
        (self.proc/'net'/name).write_text('header\n'+'\n'.join(rows), encoding='ascii')

    def socket_row(self, local, remote, inode, state='01'):
        return f'0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 1000 0 {inode}'

    def owner(self, pid, name, inode, fd='3'):
        directory = self.proc/str(pid)
        directory.mkdir(exist_ok=True)
        (directory/'comm').write_text(name+'\n', encoding='utf-8')
        (directory/'fd').mkdir(exist_ok=True)
        path = directory/'fd'/fd
        path.touch()
        self.links[path] = f'socket:[{inode}]'

    def snapshot(self):
        def readlink(path):
            result = self.links[Path(path)]
            if isinstance(result, OSError):
                raise result
            return result
        with patch('sniffer.processes.os.readlink', side_effect=readlink), patch('sniffer.processes.sys.byteorder', 'little'):
            return linux_socket_snapshot(self.proc)

    def test_ipv4_multiple_owners_sorted_and_deduplicated(self):
        self.table('tcp', [self.socket_row('0100007F:C350', '0100007F:0050', 123)])
        self.owner(21, 'zeta', 123)
        self.owner(17, 'alpha', 123)
        self.owner(17, 'alpha', 123, '4')
        self.assertEqual(self.snapshot(), {('127.0.0.1',50000,'127.0.0.1',80): 'alpha (17); zeta (21)'})

    def test_ipv6_missing_ipv4_table(self):
        self.table('tcp6', [self.socket_row('00000000000000000000000001000000:C350', '00000000000000000000000001000000:01BB', 456)])
        self.owner(9, 'python', 456)
        self.assertEqual(self.snapshot(), {('::1',50000,'::1',443): 'python (9)'})

    def test_listener_zero_inode_and_malformed_rows_ignored(self):
        self.table('tcp', [self.socket_row('00000000:0050','00000000:0000',123,'0A'),
                           self.socket_row('0100007F:0050','0100007F:C350',0),
                           self.socket_row('BAD:0050','0100007F:C350',123), 'truncated'])
        self.owner(17, 'python', 123)
        self.assertEqual(self.snapshot(), {})

    def test_vanished_and_unrelated_fds(self):
        self.table('tcp', [self.socket_row('0100007F:C350', '0100007F:0050',123)])
        self.owner(17, 'python',123)
        self.links[self.proc/'17/fd/3'] = FileNotFoundError('closed')
        self.owner(18,'other',124)
        self.links[self.proc/'18/fd/3'] = '/tmp/a-file'
        (self.proc/'19').mkdir()  # The process exits before its comm can be read.
        self.assertEqual(self.snapshot(), {})


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.resolver = ProcessResolver()
        self.resolver.psutil = None
        self.resolver.updated = 0
        self.forward = ('127.0.0.1',50000,'127.0.0.1',80)
        self.reverse = ('127.0.0.1',80,'127.0.0.1',50000)

    def packet(self, values=None, transport='TCP'):
        a,ap,b,bp = values or self.forward
        return SimpleNamespace(src=a,sport=ap,dst=b,dport=bp,transport=transport)

    def test_exact_bidirectional_tcp_only(self):
        self.resolver.mapping = {self.forward:'client (1)', self.reverse:'server (2)'}
        self.assertEqual(self.resolver.resolve(self.packet()), 'client (1); server (2)')
        self.assertEqual(self.resolver.resolve(self.packet(self.reverse)), 'client (1); server (2)')
        self.assertEqual(self.resolver.resolve(self.packet(transport='UDP')), '')
        self.assertEqual(self.resolver.resolve(self.packet(('127.0.0.1',50001,'127.0.0.1',80))), '')

    def test_linux_fallback_and_snapshot_interval(self):
        expected = {self.forward:'python (1)'}
        with patch('sniffer.capture.sys.platform','linux'), patch('sniffer.capture.time.monotonic',return_value=10), patch('sniffer.processes.linux_socket_snapshot',return_value=expected) as scan:
            self.resolver.refresh()
            self.resolver.refresh()
        self.assertEqual(scan.call_count,1)
        self.assertEqual(self.resolver.mapping,expected)
        self.assertIn('/proc', self.resolver.status)

    def test_failed_snapshot_clears_stale_ownership(self):
        self.resolver.mapping = {self.forward:'exited (1)'}
        with patch('sniffer.capture.sys.platform','linux'), patch('sniffer.capture.time.monotonic',return_value=10), patch('sniffer.processes.linux_socket_snapshot',side_effect=PermissionError('denied')):
            self.resolver.refresh()
        self.assertEqual(self.resolver.mapping,{})
        self.assertIn('不可用',self.resolver.status)


if __name__ == '__main__':
    unittest.main()

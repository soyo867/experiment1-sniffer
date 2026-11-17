"""Linux /proc TCP socket ownership without optional dependencies.

Snapshots are best-effort: short-lived sockets may disappear between scans.
Only process names, PIDs and exact socket endpoints are read, never cmdlines.
"""
import os
from pathlib import Path
import socket
import sys


def proc_endpoint(value):
    address,port=value.split(':')
    raw=bytes.fromhex(address)
    if len(raw) not in (4,16):
        raise ValueError('Invalid /proc IP address length')
    port_number=int(port,16)
    if not 0 <= port_number <= 65535:
        raise ValueError('Invalid /proc TCP port')
    if sys.byteorder=='little':
        raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
    family=socket.AF_INET if len(raw)==4 else socket.AF_INET6
    return socket.inet_ntop(family,raw),port_number


def linux_socket_snapshot(proc=Path('/proc')):
    inodes={}
    for family in ('tcp','tcp6'):
        try:
            rows=(proc/'net'/family).read_text().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields=row.split()
            if len(fields)<10 or fields[3]=='0A' or fields[9]=='0':
                continue
            try:
                src,sport=proc_endpoint(fields[1]); dst,dport=proc_endpoint(fields[2])
                inodes[fields[9]]=(src,sport,dst,dport)
            except (ValueError,OSError):
                continue
    mapping={}
    for process in proc.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            name=(process/'comm').read_text().strip()
            for fd in (process/'fd').iterdir():
                try:
                    target=os.readlink(fd)
                except OSError:
                    continue
                if target.startswith('socket:['):
                    key=inodes.get(target[8:-1])
                    if key:
                        mapping.setdefault(key,set()).add(f'{name} ({process.name})')
        except OSError:
            continue
    return {key:'; '.join(sorted(names)) for key,names in mapping.items()}

"""Bidirectional TCP connection indexing and sequence-space reassembly."""
from dataclasses import dataclass, field

from .model import endpoint

MOD = 1 << 32
MAX_STREAM_BYTES = 2 * 1024 * 1024


def relative(seq, anchor):
    """Signed distance in TCP's 32-bit sequence space (streams < 2 GiB)."""
    return ((seq-anchor + (1 << 31)) % MOD) - (1 << 31)


@dataclass
class Reassembled:
    chunks: list = field(default_factory=list)
    overlap_bytes: int = 0
    conflict_bytes: int = 0
    limited: bool = False
    missing_prefix: bool = False

    @property
    def data(self):
        """Only contiguous prefix; gaps MUST NOT be silently concatenated."""
        if not self.chunks or self.chunks[0][0] > 0:
            return b""
        return self.chunks[0][1]

    @property
    def gaps(self):
        result, end = [], 0
        for start, data in self.chunks:
            if start > end:
                result.append((end,start))
            end = start+len(data)
        return result

    def text(self):
        output, end = [], 0
        if self.missing_prefix:
            output.append("[捕获从连接中途开始，起始字节未知]\n")
        for start, data in self.chunks:
            if start > end:
                output.append(f"\n[缺失 {start-end} 字节；offset {end}..{start-1}]\n")
            output.append(data.decode("utf-8", "replace"))
            end = start+len(data)
        if self.limited:
            output.append("\n[达到每方向 2 MiB 重组上限]\n")
        return "".join(output)


def reassemble(packets):
    packets = list(packets)
    result = Reassembled()
    syn = next((p for p in packets if p.flags & 2), None)
    with_data = [p for p in packets if p.payload]
    if not with_data:
        return result
    anchor = (syn.seq+1) % MOD if syn else (with_data[0].seq + bool(with_data[0].flags & 2)) % MOD
    result.missing_prefix = syn is None
    if syn is None:
        # Earliest observed byte is the local origin when the handshake is absent.
        anchor = (anchor+min(relative((p.seq+bool(p.flags & 2)) % MOD, anchor) for p in with_data)) % MOD
    chunks, retained = [], 0
    for p in with_data:
        start = relative((p.seq+bool(p.flags & 2)) % MOD, anchor)
        data = p.payload
        if start < 0:
            data, start = data[-start:], 0
        if not data:
            continue
        pieces = [(start, data)]
        for old_start, old_data in chunks:
            old_end = old_start + len(old_data)
            remaining = []
            for pos, part in pieces:
                end = pos + len(part)
                lo, hi = max(pos,old_start), min(end,old_end)
                if lo >= hi:
                    remaining.append((pos,part))
                    continue
                result.overlap_bytes += hi-lo
                result.conflict_bytes += sum(a != b for a,b in zip(part[lo-pos:hi-pos],old_data[lo-old_start:hi-old_start]))
                if pos < lo:
                    remaining.append((pos,part[:lo-pos]))
                if hi < end:
                    remaining.append((hi,part[hi-pos:]))
            pieces = remaining
            if not pieces:
                break
        for pos, part in pieces:
            room = MAX_STREAM_BYTES-retained
            if len(part) > room:
                result.limited = True
            if room:
                chunks.append((pos,part[:room]))
                retained += len(part[:room])
        chunks.sort(key=lambda pair: pair[0])
        merged = []
        for pos, part in chunks:
            if merged and merged[-1][0]+len(merged[-1][1]) == pos:
                old_pos, old_data = merged[-1]
                merged[-1] = (old_pos, old_data+part)
            else:
                merged.append((pos,part))
        chunks = merged
        if result.limited:
            break
    result.chunks = chunks
    return result


@dataclass
class Flow:
    id: int
    a: tuple
    b: tuple
    packets: list = field(default_factory=list)
    syn_sequence: int | None = None
    closed: bool = False
    fin_sources: set = field(default_factory=set)

    @property
    def label(self):
        return f"#{self.id}  {endpoint(*self.a)}  ↔  {endpoint(*self.b)}"

    def direction(self, packet):
        return 0 if (packet.src,packet.sport) == self.a else 1

    def assembled(self, direction):
        return reassemble(p for p in self.packets if self.direction(p) == direction)

    def export_text(self):
        lines = [self.label, f"Packets: {len(self.packets)}", ""]
        for direction, name in [(0,"A → B"),(1,"B → A")]:
            result = self.assembled(direction)
            lines.extend([name, f"Overlap={result.overlap_bytes} Conflict={result.conflict_bytes} Gaps={len(result.gaps)}",result.text(),""])
        return "\n".join(lines)


class FlowIndex:
    def __init__(self):
        self.flows, self.active = [], {}

    def add(self, p):
        if p.transport != "TCP":
            return
        ends = sorted(((p.src,p.sport), (p.dst,p.dport)))
        key = (p.ip_version, *ends)
        flow = self.active.get(key)
        new_syn = p.flags & 2 and not p.flags & 16
        if flow is None or (new_syn and (flow.closed or flow.syn_sequence != p.seq)):
            a, b = (p.src,p.sport), (p.dst,p.dport)
            if p.flags & 2 and p.flags & 16:  # SYN/ACK first: recover client/server orientation.
                a, b = b, a
            flow = Flow(len(self.flows), a, b, syn_sequence=p.seq if new_syn else None)
            self.flows.append(flow)
            self.active[key] = flow
        if p.flags & 1:
            flow.fin_sources.add((p.src,p.sport))
        if p.flags & 4 or len(flow.fin_sources) == 2:
            flow.closed = True
        p.flow_id = flow.id
        flow.packets.append(p)

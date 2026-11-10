from dataclasses import dataclass, field


@dataclass(slots=True)
class Layer:
    name: str
    fields: dict
    start: int = 0
    end: int = 0


@dataclass(slots=True)
class Packet:
    number: int
    timestamp: float
    raw: bytes
    wire_length: int
    linktype: int = 1
    layers: list[Layer] = field(default_factory=list)
    protocol: str = "UNKNOWN"
    src: str = ""
    dst: str = ""
    ip_version: int = 0
    transport: str = ""
    sport: int | None = None
    dport: int | None = None
    seq: int = 0
    ack: int = 0
    flags: int = 0
    payload: bytes = b""
    info: str = ""
    warnings: list[str] = field(default_factory=list)
    flow_id: int | None = None
    process: str = ""

    @property
    def protocols(self):
        return {layer.name.lower() for layer in self.layers} | {self.protocol.lower()}

    @property
    def source(self):
        return endpoint(self.src, self.sport)

    @property
    def destination(self):
        return endpoint(self.dst, self.dport)


def endpoint(address, port):
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

"""A small display-filter language. Recursive descent, no eval or exec.

Grammar: or -> and -> not -> (expr) | protocol | field operator value
Examples: tcp and port == 8080; ipv6 or icmp; http and ip.addr == 127.0.0.1
"""
import ipaddress
import re


class FilterError(ValueError):
    pass


TOKEN = re.compile(r'\s*(\(|\)|==|!=|>=|<=|>|<|&&|\|\||!|"(?:[^"\\]|\\.)*"|[^\s()=!<>|&]+)')
PROTOCOLS = {"tcp", "udp", "http", "dns", "tls", "arp", "ipv4", "ipv6", "icmp", "icmpv6", "ethernet", "vlan"}
NUMERIC = {"port", "tcp.port", "udp.port", "src.port", "dst.port", "length", "frame.len", "stream", "tcp.stream"}
FIELDS = NUMERIC | {"ip.addr", "ip.src", "ip.dst", "protocol", "info", "process"}


def compile_filter(expression):
    if len(expression) > 4096:
        raise FilterError("过滤表达式超过 4096 字符")
    if not expression.strip():
        return lambda p: True
    tokens, offset = [], 0
    while offset < len(expression):
        if not expression[offset:].strip():
            break
        match = TOKEN.match(expression, offset)
        if not match:
            raise FilterError(f"无效字符，位置 {offset+1}")
        tokens.append(match.group(1))
        offset = match.end()
    if len(tokens) > 256:
        raise FilterError("过滤表达式超过 256 个 token")
    parser = _Parser(tokens)
    predicate = parser.parse_or()
    if parser.peek() is not None:
        raise FilterError(f"多余内容：{parser.peek()}；条件之间使用 and / or")
    return predicate


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.pos = tokens, 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        item = self.peek()
        if item is None:
            raise FilterError("表达式不完整")
        self.pos += 1
        return item

    def parse_or(self):
        left = self.parse_and()
        while self.peek() in ("or", "||"):
            self.take()
            right = self.parse_and()
            left = lambda p, a=left, b=right: a(p) or b(p)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.peek() in ("and", "&&"):
            self.take()
            right = self.parse_not()
            left = lambda p, a=left, b=right: a(p) and b(p)
        return left

    def parse_not(self):
        if self.peek() in ("not", "!"):
            self.take()
            inner = self.parse_not()
            return lambda p: not inner(p)
        if self.peek() == "(":
            self.take()
            inner = self.parse_or()
            if self.take() != ")":
                raise FilterError("缺少右括号")
            return inner
        field = self.take().lower()
        if field in PROTOCOLS:
            return lambda p: field in p.protocols
        if field not in FIELDS:
            raise FilterError(f"未知协议或字段：{field}")
        operator = self.take()
        if operator not in ("==", "!=", ">", "<", ">=", "<=", "contains"):
            raise FilterError("运算符应为 == != > < >= <= contains")
        value = self.take()
        if value.startswith('"'):
            value = value[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        if field in NUMERIC:
            try:
                value = int(value)
            except ValueError:
                raise FilterError(f"{field} 需要整数") from None
            if operator == "contains":
                raise FilterError("整数不能使用 contains")
        elif operator not in ("==", "!=", "contains"):
            raise FilterError("文本字段支持 == != contains")
        if field.startswith("ip.") and operator in ("==", "!="):
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                raise FilterError("IP 字段需要有效的 IPv4 或 IPv6 地址") from None
        compare = {"==": lambda x:x == value, "!=": lambda x:x != value,
                   ">":lambda x:x > value, "<":lambda x:x < value,
                   ">=":lambda x:x >= value, "<=":lambda x:x <= value,
                   "contains":lambda x:str(value).casefold() in str(x).casefold()}[operator]
        def predicate(p):
            values = field_values(p, field)
            # Missing fields never match, including !=. For pairs, != means neither endpoint equals.
            return bool(values) and (all(compare(x) for x in values) if operator == "!=" else any(compare(x) for x in values))
        return predicate


def field_values(p, field):
    if field in ("tcp.port", "udp.port") and p.transport.lower() != field.split(".")[0]:
        return []
    if field.startswith("ip.") and not p.ip_version:
        return []
    values = {"port":(p.sport,p.dport), "tcp.port":(p.sport,p.dport), "udp.port":(p.sport,p.dport),
              "src.port":(p.sport,), "dst.port":(p.dport,), "length":(p.wire_length,), "frame.len":(p.wire_length,),
              "stream":(p.flow_id,), "tcp.stream":(p.flow_id,), "ip.addr":(p.src,p.dst), "ip.src":(p.src,),
              "ip.dst":(p.dst,), "protocol":(p.protocol.lower(),), "info":(p.info,), "process":(p.process,)}
    return [v for v in values[field] if v is not None]

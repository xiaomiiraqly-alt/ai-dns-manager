"""Small, bounded DNS wire helpers. Forwarding preserves upstream RDATA verbatim."""
import secrets
import socket
import struct

MAX_WIRE = 65535


def read_name(data, pos):
    labels, seen, end, wire_size = [], set(), None, 1
    for _ in range(128):
        if pos >= len(data) or pos in seen:
            raise ValueError("Truncated or cyclic DNS name")
        seen.add(pos)
        size = data[pos]
        if size & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("Truncated DNS pointer")
            pointer = ((size & 63) << 8) | data[pos + 1]
            if pointer < 12 or pointer >= pos:
                raise ValueError("Invalid DNS compression pointer")
            if end is None:
                end = pos + 2
            pos = pointer
            continue
        if size & 0xC0:
            raise ValueError("Invalid DNS label")
        pos += 1
        if size == 0:
            return tuple(labels), end if end is not None else pos
        if pos + size > len(data):
            raise ValueError("Truncated DNS label")
        wire_size += size + 1
        if wire_size > 255:
            raise ValueError("DNS name too long")
        labels.append(data[pos:pos + size].lower())
        pos += size
    raise ValueError("Too many DNS labels or compression pointers")


def header(data):
    if not 12 <= len(data) <= MAX_WIRE:
        raise ValueError("Invalid DNS message length")
    return struct.unpack_from("!6H", data)


def question(data):
    _, _, qd, _, _, _ = header(data)
    if qd != 1:
        raise ValueError("Expected one DNS question")
    labels, pos = read_name(data, 12)
    if pos + 4 > len(data):
        raise ValueError("Missing DNS question fields")
    kind, cls = struct.unpack_from("!HH", data, pos)
    return labels, kind, cls, pos + 4


def records(data):
    _, _, _, an, ns, ar = header(data)
    pos = question(data)[3]
    result = []
    for section, count in enumerate((an, ns, ar)):
        for _ in range(count):
            owner, pos = read_name(data, pos)
            if pos + 10 > len(data):
                raise ValueError("Truncated DNS RR header")
            kind, cls, ttl, size = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            if pos + size > len(data):
                raise ValueError("Truncated DNS RDATA")
            result.append((section, owner, kind, cls, ttl, pos, size))
            pos += size
    if pos != len(data):
        raise ValueError("Trailing bytes in DNS message")
    return result


def question_name(packet):
    labels, _, _, end = question(packet)
    try:
        return b".".join(labels).decode("ascii"), end
    except UnicodeDecodeError as exc:
        raise ValueError("Non-ASCII DNS question") from exc


def validate_query(packet):
    _, flags, _, an, ns, _ = header(packet)
    if flags & 0x8000 or flags & 0x7800 or an or ns:
        raise ValueError("Only ordinary DNS queries are supported")
    labels, kind, cls, _ = question(packet)
    if cls != 1 or kind in (251, 252):
        raise ValueError("Only IN queries; zone transfers are unsupported")
    if any(r[2] in (250, 24) for r in records(packet)):
        raise ValueError("Signed queries are unsupported")
    return labels, kind, cls


def validate_response(query, answer):
    qi, qflags, _, _, _, _ = header(query)
    ai, flags, _, _, _, _ = header(answer)
    if ai != qi or not flags & 0x8000 or (flags & 0x7800) != (qflags & 0x7800):
        raise ValueError("DNS response ID, QR, or opcode mismatch")
    if question(query)[:3] != question(answer)[:3]:
        raise ValueError("DNS response question mismatch")
    # A truncated UDP response may intentionally omit an incomplete final RR.
    if not flags & 0x0200:
        records(answer)
    return flags & 15


def make_query(name, kind=1):
    if name == '.':
        labels = []
    else:
        labels = [part.encode("idna") for part in name.rstrip('.').split('.')]
    if any(not x or len(x) > 63 for x in labels):
        raise ValueError("Invalid DNS label")
    qname = b''.join(bytes([len(x)]) + x for x in labels) + b'\0'
    if len(qname) > 255:
        raise ValueError("DNS name too long")
    return struct.pack('!6H', secrets.randbits(16), 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', kind, 1)


def reply(query, rcode=2, truncated=False):
    try:
        _, flags, _, _, _, _ = header(query)
        labels, kind, cls, _ = question(query)
        qname = b''.join(bytes([len(x)]) + x for x in labels) + b'\0'
        # Re-encode the question so no compression pointers reference discarded data.
        result_flags = 0x8080 | (flags & 0x0110) | rcode | (0x0200 if truncated else 0)
        return query[:2] + struct.pack('!5H', result_flags, 1, 0, 0, 0) + qname + struct.pack('!HH', kind, cls)
    except ValueError:
        return b''


def udp_limit(query):
    for section, _, kind, cls, _, _, _ in records(query):
        if section == 2 and kind == 41:
            return max(512, min(cls, 1232))
    return 512


def a_records(answer):
    if header(answer)[1] & 15:
        return []
    rr = records(answer)
    reachable = {question(answer)[0]}
    for _ in range(16):
        before = len(reachable)
        for section, owner, kind, cls, _, pos, size in rr:
            if section == 0 and owner in reachable and kind == 5 and cls == 1:
                target, end = read_name(answer, pos)
                if end != pos + size:
                    raise ValueError('Invalid CNAME RDATA')
                reachable.add(target)
        if len(reachable) == before:
            break
    return sorted({socket.inet_ntoa(answer[pos:pos+size])
                   for section, owner, kind, cls, _, pos, size in rr
                   if section == 0 and owner in reachable and kind == 1 and cls == 1 and size == 4})

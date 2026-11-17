"""Read-only DNS + TLS diagnostics using only the Python standard library."""
import argparse
import ipaddress
import json
import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from pathlib import Path


def dns_query(name: str, server: str, timeout: float) -> list[str]:
    """Query a DNS server for IPv4 A records over UDP/53 (no recursion through OS DNS)."""
    qid = int(time.time_ns() & 0xffff)
    labels = name.rstrip(".").split(".")
    if not labels or any(not part or len(part.encode("idna")) > 63 for part in labels):
        raise ValueError("Invalid DNS name")
    qname = b"".join(bytes([len(x.encode("idna"))]) + x.encode("idna") for x in labels) + b"\x00"
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, sender = sock.recvfrom(4096)
    if sender[0] != server or len(data) < 12:
        raise ValueError("Invalid DNS response")
    rid, flags, qd, an, _, _ = struct.unpack_from("!HHHHHH", data)
    if rid != qid or not flags & 0x8000 or flags & 0x000f:
        raise ValueError("DNS response ID, QR, or RCODE invalid")

    def skip_name(pos: int) -> int:
        for _ in range(128):
            if pos >= len(data):
                raise ValueError("Truncated DNS name")
            size = data[pos]
            if size & 0xc0 == 0xc0:
                if pos + 1 >= len(data):
                    raise ValueError("Truncated DNS pointer")
                return pos + 2
            if size & 0xc0:
                raise ValueError("Invalid DNS label")
            pos += 1
            if size == 0:
                return pos
            pos += size
        raise ValueError("DNS name too long")

    pos = 12
    for _ in range(qd):
        pos = skip_name(pos) + 4
    ips = []
    for _ in range(an):
        pos = skip_name(pos)
        if pos + 10 > len(data):
            raise ValueError("Truncated DNS answer")
        kind, cls, _, size = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        if pos + size > len(data):
            raise ValueError("Truncated DNS RDATA")
        if kind == 1 and cls == 1 and size == 4:
            ips.append(socket.inet_ntoa(data[pos:pos+4]))
        pos += size
    return sorted(set(ips))


def check_tls(host: str, ip: str, timeout: float) -> dict:
    started = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as conn:
                return {"ok": True, "latency_ms": round((time.monotonic()-started)*1000), "tls_version": conn.version()}
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return {"ok": False, "error": str(exc)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only AI DNS diagnostics")
    parser.add_argument("--config", default="config/providers.json")
    parser.add_argument("--output", default="diagnostics.json")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    host = config["target"]
    timeout = float(config.get("timeout_seconds", 4))
    if not 0 < timeout <= 30:
        parser.error("timeout_seconds must be between 0 and 30")
    results = []
    for provider in config["providers"]:
        name, server = provider["name"], str(ipaddress.IPv4Address(provider["ip"]))
        item = {"name": name, "dns_server": server}
        started = time.monotonic()
        try:
            addresses = dns_query(host, server, timeout)
            item["dns"] = {"ok": True, "addresses": addresses, "latency_ms": round((time.monotonic()-started)*1000)}
            item["tls"] = [{"ip": ip, **check_tls(host, ip, timeout)} for ip in addresses[:4]]
        except (OSError, ValueError, TimeoutError) as exc:
            item["dns"] = {"ok": False, "error": str(exc)}
            item["tls"] = []
        results.append(item)
        print(f"{name}: DNS={item['dns']['ok']} addresses={item['dns'].get('addresses', [])} TLS_OK={sum(x['ok'] for x in item['tls'])}", flush=True)
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "target": host, "results": results, "note": "DNS/TLS only. No API availability assertion."}
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()

"""DNS-over-HTTPS JSON diagnostics. No API keys or routing changes."""
import ipaddress
import json
import ssl
import urllib.parse
import urllib.request


def doh_query(host: str, endpoint: str, timeout: float) -> list[str]:
    """Query a trusted HTTPS JSON DNS endpoint and return validated IPv4 answers."""
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("DoH endpoint must be an HTTPS URL without credentials or fragment")
    query = urllib.parse.urlencode({"name": host, "type": "A"})
    url = endpoint + ("&" if parsed.query else "?") + query
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "ai-dns-manager/0.2"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
        if response.status != 200:
            raise ValueError(f"DoH HTTP status {response.status}")
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("DoH response too large")
    data = json.loads(raw)
    if data.get("Status") != 0:
        raise ValueError(f"DoH DNS status {data.get('Status')}")
    addresses = []
    for record in data.get("Answer", []):
        if record.get("type") == 1:
            try:
                addresses.append(str(ipaddress.IPv4Address(record["data"])))
            except (KeyError, ipaddress.AddressValueError) as exc:
                raise ValueError("Invalid DoH A record") from exc
    return sorted(set(addresses))

# Provider sources and trust

A resolver IP is not necessarily an HTTPS relay IP. Ask the resolver for the AI hostname first; then verify TLS against the **returned** address. Never disable certificate checks to make a candidate pass. Publicly announced endpoints are not a reliability or privacy endorsement.

| Project | Published configuration / handling here | Primary source |
| --- | --- | --- |
| DNS-AI | DoH `https://dns.dns-ai.ru/dns-query`, DoT `dns.dns-ai.ru`, bootstrap IPv4 `194.87.196.13`, `45.151.102.219`. Included as diagnostic candidates. Plain UDP is not their documented connection method. | https://dns-ai.ru/ |
| ZombieDNS | DoH `https://dns.zombiez.ru/dns-query`, DoT `dns.zombiez.ru`, IPv4 `186.243.168.31`. Included as candidates, not asserted to work with authenticated Gemini. | https://dns.zombiez.ru/ |
| Comss.one | Published DoH `https://dns.comss.one/dns-query` and DoT `dns.comss.one`. Bootstrap IP must be separately verified before adding; no guessed address is enabled. | https://www.comss.ru/page.php?id=7315 |
| Keyoneday | IPv4 `2.58.127.63`, DoH `https://dns.keyoneday.ru/dns-query`. Operator states that its supported path uses Russian source IPs; not automatically enabled on a foreign VPN exit. | https://keyoneday.ru/dns.html |
| MagicDNS | Main configuration sections currently contain `СКОРО` placeholders. Not enabled using guessed endpoints. Verify an actual supported profile before adding. | https://magicdns.ru/ |
| Mahiron-hq/ai-dns | Windows selection/rollback tool, not another DNS provider. Conceptual reference only; no source code copied into this MIT project. | https://github.com/Mahiron-hq/ai-dns |

Endpoints can change. This version deliberately does not scrape websites and silently activate newly discovered providers. Review changes, configure explicit bootstrap addresses and rerun diagnostics from the actual deployment network.

## Protocol references

- DoH wire format: https://www.rfc-editor.org/rfc/rfc8484.html
- DoT framing: https://www.rfc-editor.org/rfc/rfc7858.html
- Quad9 operational guidance: https://docs.quad9.net/Quad9_For_Organizations/DNS_Forwarder_Best_Practices/

DoH uses HTTP/1.1 POST with `application/dns-message`. Protocol support is deliberately narrower than a general-purpose recursive DNS server. There is no independent DNSSEC validator or cache.

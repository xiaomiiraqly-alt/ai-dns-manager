# Security and scope

Experimental private-network software, not a hardened public recursive resolver.

- Keep the listener private. Defaults bind published ports to loopback; application ACLs and concurrency limits are defense in depth.
- TLS hostname and certificate-chain verification are mandatory. No `verify=false`, disabled certificate checks, redirects or user-supplied proxy environment settings in DNS transports.
- Explicit bootstrap IPs avoid circular resolution of upstream hostnames. Resolvers and relay addresses are separate concepts.
- Upstream responses must match the randomized transaction, question, type, class and opcode. Truncated UDP responses retry TCP. Malformed data is rejected.
- Smart DNS operators see connection/DNS metadata and control availability. End-to-end TLS is not a blanket trust endorsement. Do not send sensitive material to unreviewed infrastructure.
- Diagnostics skip TLS connections to non-public addresses returned for public service probes. Gemini API probes require an explicit flag; keys come only from process environment and are never written to reports.
- Region, authorization, quota and model errors are distinct. Respect service eligibility requirements and terms. This project does not promise to make an ineligible account eligible.
- No unattended privileged installer, host DNS changes, Docker-daemon restarts, VPN private keys, secret files, public DNS bindings or Docker-socket mounts.
- HTTP/1.1 DoH connections are per-query; connection pooling, caching, advanced abuse protection, persistent route state and authenticated API-aware monitoring are not implemented.

Report reproducible issues through GitHub without secrets. Do not publish API keys, private VPN profiles, personal request content or unredacted server dumps.

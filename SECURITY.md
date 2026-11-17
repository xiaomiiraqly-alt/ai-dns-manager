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
- HTTP/1.1 DoH connections are per-query; connection pooling, DNS-answer caching and advanced public-resolver abuse protection are not implemented. Service-aware monitoring and persisted plans are opt-in in v0.4.

Report reproducible issues through GitHub without secrets. Do not publish API keys, private VPN profiles, personal request content or unredacted server dumps.

## v0.4 additions

Provider auto-update accepts only configured GitHub/jsDelivr HTTPS data feeds; no redirects or downloaded executable code. Data is size-bounded, parsed, public-address filtered, cached by source identity and replaced atomically. Bundled original provider data retains Apache-2.0 attribution. Credentials/probe definitions come from trusted local service configuration, never a provider feed.

Real API calls require service AND DNS-provider allowlists. The reserved `reference` provider identity cannot be injected from a remote feed. Service-aware routing treats unknown/error/CAPTCHA responses conservatively and does not turn a fake-key 401 into a generation success. Missing required coverage prevents a new plan. Private/reserved probe destinations are rejected; host IPv6 is not changed. AAAA and HTTPS/SVCB hints are suppressed only for monitored domains in service-aware mode because only their IPv4 route has been tested.

Web profiles check HTTP entry points, not signed-in sessions or model execution. Endpoint sampling and cached application connections limit what a DNS-only solution can prove. Do not present a JSON catalogue entry as a confirmed working AI service.

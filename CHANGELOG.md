# Changelog

## 0.3.0 — encrypted private DNS service (experimental)

- Add RFC 8484 binary DoH and authenticated DoT, numeric bootstrap endpoints and strict TLS verification.
- Validate DNS transaction/question/record framing; reject malformed/compressed-name loops and zone-transfer requests; retry truncated UDP answers over TCP.
- Add private UDP/TCP listeners, CIDR ACLs, bounded concurrency, request budgets, clean termination and local healthchecks.
- Add sticky within-group failover, cooldown, recovery probes and structured event logs. No API-health claims based on DNS success.
- Add read-only parallel provider diagnostics and explicit Gemini generation checks with categorized errors and no secret output.
- Add a Docker-only pilot installer, immutable configuration snapshots, managed-container ownership checks and rollback attempts; Compose remains optional.
- Correct provider testing methodology: probe addresses returned by DNS, not the resolver address as an assumed relay.
- Expand offline tests to cover real local UDP/TCP/DoH/DoT servers, failover, malformed input, TLS rejection and installer rollback.
- Fix the read-only Docker diagnostic default: report to stdout instead of an unwritable filesystem.

## 0.1 / early 0.2 prototype

Read-only DNS/TLS diagnostics, basic UDP/TCP forwarding and limited tests. Not a production VPN integration.

# Changelog

## 0.8.1 — continuously renewed Gemini evidence and automatic gateway activation

- Refresh the evidence timestamp of an **unchanged, actually generation-verified** mandatory Gemini route on each successful scan, even while optional service changes wait for switch confirmation.
- Track separate per-service evidence timestamps so untested optional AI routes cannot inherit Gemini's renewed lifetime.
- Keep verified active upstreams and independent backup proof; drop optional routes when their own evidence expires.
- Make `awg_dns_gateway.py install` automatically wait for an upcoming fresh generation-confirmed plan (maximum four minutes by default), without bypassing the security requirement.
- Add offline tests for optional-route churn, missing Gemini generation, expired optional evidence, per-service gateway freshness and bounded proof waits.
- Old Comss AUTH_GATE snapshots are still rejected. Active VPN/host DNS and existing peer configurations remain unchanged until the operator explicitly enables the private gateway.

## 0.8.0 — Karakeep split DNS over private AWG gateway

- Add isolated split DNS sidecar in existing Karakeep AWG client network namespace, without restarting the VPN or application containers.
- Forward mandatory Gemini and other required AI domains to the previously verified egress private DNS gateway; only preferred AI domains may fall back to original resolvers.
- Preserve current Karakeep Chrome/web and Docker service names through their original DNS resolvers, including Docker's 127.0.0.11 where present.
- Back up each Docker-managed `resolv.conf` in a protected local manifest, update the existing file in place only after private and ordinary DNS checks, and restore on failure or uninstall.
- Enforce same-AWG-network-namespace checks for web/Chrome; refuse unexpected Docker resolver paths and unmanaged sidecars.
- Add offline integration tests for installer, non-public binding, unchanged Docker resolver identity, namespace checks, and rollback.
- Explicitly document runtime-only persistence: a Docker/Compose container recreation may reset DNS, requiring a controlled follow-up.

## 0.7.0 — private AmneziaWG DNS gateway (opt-in)

- Add an opt-in DNS UDP/TCP gateway on the existing AWG container's **private** interface port 53, forwarding queries to AI DNS Manager.
- Join the manager to the existing private AWG Docker network while preserving its default outbound route priority.
- Fail closed without a recent actual `GENERATION_OK` Gemini plan; reject unowned existing containers, non-private WireGuard addresses, and stale gateway forwarding.
- Never modify the host resolver, firewall, existing AWG container configuration, peer profiles or route tables; no published port 53.
- Add uninstall/rollback command, source-level offline tests and deployment instructions, including explicit peer DNS requirements.

## 0.6.1 — stale-plan and fallback evidence hardening

- Persist independent verification status and evidence for each selected backup.
- Require every installed mandatory route and fallback to satisfy the service's configured evidence threshold; refuse forged/stale AUTH_GATE plans for required Gemini generation.
- Archive incompatible or unauthenticated active plans on service startup rather than leaving an old Comss AUTH_GATE snapshot labelled active.
- Distinguish an observable disk snapshot from confirmed live in-memory routing in the manager status command.
- Add offline regression tests for invalid primary routes, region errors, invalid backups, verified backups and safe archiving of legacy plans.

## 0.6.0 — verified-generation provider selection and safer upgrades

- Require `GENERATION_OK` and evidence level 4 for mandatory Gemini API; a fake-key `AUTH_GATE` cannot select or renew a Gemini route.
- Migrate legacy local manager settings without overwriting the original: authorize Gemini checks, prioritize trusted DNS-AI, and avoid unneeded reference API calls.
- Reserve mandatory scan capacity for approved authenticated providers even with many previous routes; keep previous healthy route priority bounded.
- Support Karakeep's OpenAI-compatible Gemini environment-variable aliases without exposing credentials.
- Automatically reuse the private root-owned `/etc/ai-dns-manager/gemini.env` secrets file on subsequent Docker installs.
- Allow deliberate `--archive-rollback` to preserve an existing rollback container under a timestamped name instead of deleting it.
- Add synthetic end-to-end tests reproducing the observed Comss/WebShift region refusals versus successful DNS-AI generation, including failover, backup eligibility and missing keys.
- Explicitly separate DNS listener health, model-generation proof, and the still-unconfigured VPN client DNS route.

## 0.5.1 — idempotent service-state permissions during reinstall

- Fix repeated `install.py install --service-aware` failing with `PermissionError: /state` after the state directory was handed to UID/GID 65534.
- Leave correctly owned private state directories unchanged; only repair ownership/permissions when needed using a network-isolated helper with narrowly scoped CHOWN/FOWNER capabilities.
- Verify the directory's final owner/mode before switching any existing managed container; refuse symbolic-link state directories.
- Add regressions covering existing state, permission repair, failed repair and symlink rejection. An unsuccessful preflight leaves the old managed container untouched.

## 0.5.0 — bounded staged service-aware scanner

- Replace the 136-endpoint × 44-service first-round matrix with DNS prefilter, required-service validation and a small rotating optional-service frontier.
- Default to at most 12 candidates per required service, four for preferred, and eight workers, with bounded DNS/HTTP timeouts and per-phase budgets.
- Record `scan-progress.json` after each phase, including which mandatory services lack a verified route.
- Distinguish `NOT_SCANNED` from `UNAVAILABLE` without accepting untested candidates.
- Preserve authentication opt-in, per-service evidence levels, current route preference and fail-closed mandatory routing.
- Clarify Docker listener health versus AI route readiness in the installer.
- Add offline scale and negative-path regressions using the actual scanner under a 136 × 44 synthetic catalogue.

## 0.4.0 — service-aware selection (experimental)

- Add 44 extensible web/API profiles with required/preferred/off modes and explicit evidence thresholds.
- Compare ordinary-DNS and Smart-DNS paths using actual returned target addresses; add no-key and opt-in authenticated probes.
- Rank required coverage before all preferred scores, choose per-service reserves, use sticky selection, failure rounds and cooldown.
- Restore provider feed auto-updates, six-hour cache, source validation, stale-good fallback, deduplication, exclusions and address discovery.
- Add continuous private service manager and Docker-only installer mode with protected state and optional local secrets file.
- Preserve original provider DATA license/notice; do not copy or execute original Windows code.
- Add offline tests for service classification, ranking, cached updates, credential boundaries and end-to-end scan/selection/DNS forwarding.
- Do not claim universal service/model support or real VPS access until runtime checks pass.

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

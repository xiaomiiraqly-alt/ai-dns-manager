# Changelog

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

# Service-aware selection (v0.4)

## Restore the original behavior, adapted to a server

The Windows original selects according to usable required/preferred services, then applies a primary, backup and per-domain NRPT exceptions. This implementation uses a private DNS listener and per-service upstream groups instead of NRPT. It does not edit Windows adapters, browser policies or the Linux system resolver.

Required coverage dominates every preferred score combined. The selector can cover different required services through different providers. A backup must pass the SAME service's threshold, not merely answer DNS. If any required service lacks a verified route, the proposal is not applied. Last-good state remains only until its configured expiry. A recovered or faster provider does not immediately displace a healthy active route.

## Profiles and modes

`config/services.json` is the trusted local catalogue. `config/manager.json` contains local policy. Modes are `required`, `preferred`, `off`. `service_overrides.modes` changes the selected modes; `service_overrides.minimum_evidence` changes how much proof is required. Every profile has an exact checked hostname, relative HTTP path, kind (`web` or `api`) and DNS route suffixes.

Example local settings:

```json
{
  "service_overrides": {
    "modes": {
      "gemini-api": "required",
      "chatgpt": "preferred",
      "claude": "preferred",
      "suno": "off"
    },
    "minimum_evidence": {"gemini-api": "generation"},
    "custom_services": [
      {
        "id": "my-ai-service",
        "name": "My AI service",
        "domain": "ai.example.org",
        "kind": "web",
        "path": "/",
        "mode": "preferred",
        "minimum_evidence": "http"
      }
    ]
  }
}
```

This is a fragment to merge into `manager.json`, not a complete replacement. `example.org` is an illustration, not a real provider recommendation. A new profile requires no Python changes. Unknown service IDs, duplicate route ownership, private hostnames, malformed URLs and literal keys in credential-variable fields are rejected.

Two HTTP paths on the same hostname cannot be given different DNS routes. To use an API on the same hostname as a web profile, turn the overlapping profile off and define its replacement. The starter OpenRouter web profile therefore does not pretend to separately route its same-host API.

## Four evidence levels

| Minimum | What is required | What it does NOT prove |
|---|---|---|
| `endpoint` | Verified TLS and a recognized API gate/public API response | Working credentials or generation |
| `http` | Successful, non-challenge, bounded HTTP/public API response | Logged-in browser use or paid operations |
| `authenticated` | An explicit credentialed JSON operation succeeded and matched its success field, or text generation succeeded | All operations/models on that account |
| `generation` | Nonempty text from an authorized OpenAI-compatible/Anthropic generation request | Image/audio/video jobs or every model |

`AUTH_GATE` (often a known invalid-key response) only has endpoint evidence. An arbitrary 400/401/403, a login redirect to another host, a CAPTCHA, or a TLS handshake does not count as usable generation. `REGION_BLOCKED`, `AUTH_OR_PERMISSION`, `QUOTA_OR_RATE_LIMIT`, `MODEL_OR_CONFIGURATION`, `BOT_CHALLENGE`, `NETWORK_ERROR` and `TLS_ERROR` remain separate.

No unauthenticated probe can establish account/model usability. To make Karakeep's real Gemini generation mandatory, choose `generation`, opt in to its credential check and supply its existing key/model locally. Without a key, this mode truthfully reports missing evidence and does not apply a pretend-success plan.

## Anonymous and real-key checks

Every enabled profile gets a no-key or deliberately-invalid-key check. Real requests need BOTH:

```json
{
  "authorized_services": ["gemini-api"],
  "credential_provider_ids": ["dns-ai", "reference"],
  "max_api_requests": 8
}
```

These IDs are explicit operator trust decisions, not recommendations. Default `authorized_services` is empty. The model and key come from `GEMINI_MODEL` and `GEMINI_API_KEY`, or the specific environment-variable names in a custom profile. The legacy single-target Gemini command still accepts the Karakeep aliases.

OpenAI-compatible and Anthropic adapters use a short text prompt and a bounded token limit. The generic `json` adapter supports an explicit GET/POST, configured authorization header and a JSON success pointer. It does not treat HTTP 200 alone as success. No account content or error-body text is saved to reports. Certificates are verified before HTTP headers containing keys are sent. Redirects are never followed with credentials.

With the installer, an optional secrets env-file must be outside the repository with permissions 600 or stricter:

```bash
python3 install.py install --service-aware --secrets-file /root/ai-dns.env
```

The file contains `GEMINI_API_KEY=...` and `GEMINI_MODEL=...` (or variables declared by the selected profiles). Do not paste it into chat or GitHub. Docker administrators can inspect container environment variables; this is not an encrypted secret store. Generated reports contain neither keys nor prompt/response text.

API requests are deduplicated by service/address within a round. The active route is checked first when credentials are enabled. A global per-round request budget prevents unbounded generation across the catalogue. Account/key/quota errors cannot be “fixed” by silently declaring an untested DNS provider healthy.

## Ordinary DNS versus Smart DNS

Reference resolvers and Smart DNS candidates are both tested from the deployment process's network. No test disables or bypasses the existing VPN. An address differing from the reference is a clue, **not proof** that it is a relay: CDN/anycast answers may differ legitimately.

Each target address is queried through its candidate resolver, then HTTPS uses that exact returned address with the original Host/SNI/certificate name. The resolver's own IP is never blindly treated as the target relay. Up to sixteen returned IPv4 addresses are probed; more than sixteen or any unchecked returned addresses make a route ineligible. Any failing address disqualifies that route.

## Automatic provider updates

The original project's JSON catalogue and DnsSwitch's presets are refreshed on expiry (six hours by default), with explicit GitHub/jsDelivr locations. Only data is downloaded. Bounds, schema/format validation, public-address checks, source identity, atomic replacement and last-good cache prevent a bad download from erasing working data. Hostname discovery obtains current bootstrap candidates using explicit reference resolvers. Local exclusions and custom providers are preserved.

`--offline` disables downloads and hostname discovery but **does not** disable service network probes. A stale valid cache and the bundled seed are usable offline. There is no claim that a provider listed by either project is trustworthy or supports your location/API.

## Running and state

```bash
python3 -m ai_dns_manager.manager validate
python3 -m ai_dns_manager.manager scan --state-dir data/service-manager
python3 -m ai_dns_manager.manager serve --state-dir data/service-manager
python3 -m ai_dns_manager.manager status --state-dir data/service-manager
```

`scan` is diagnostic and never activates routing. `serve` is an opt-in loopback DNS server plus continuous controller. The first usable full-required proposal can be applied; subsequent route changes require consecutive failures and honor cooldown. Provider-list refresh and service checks are separate intervals. Reference settings: service round every 300 seconds, source refresh 21600 seconds, last-good route lifetime 1800 seconds. Configuration can raise a staged-scan budget or disable unnecessary profiles; untested candidates are explicitly marked, never counted as successful.

A temporary failure cannot erase the active plan. Expired state, changed service/provider policy, or missing required evidence cannot be reused as proof of success. Credentialed plans are rechecked after process restart. Updates swap the whole validated plan atomically. DNS changes affect new lookups; existing browser caches and TLS connections are not forcibly cleared.

Files: `scan-progress.json` (current phase and counts), `catalogue.json` (source provenance), `service-report.json` (anonymous and keyed outcomes), `proposed-plan.json` (ranking, gaps, routes), `active-plan.json` (last applied plan), and validated source cache. State is local and Git-ignored. The process listener healthcheck remains separate from service availability.

## Deployment boundary

Neither `scan` nor `serve` changes the VPS's system DNS, AmneziaWG, NAT, clients or public port 53. The installer publishes only 127.0.0.1:5353. Connecting VPN clients still requires a deliberately chosen private DNS address and verified two-way routes. There is no blanket claim that all listed products work on the user's VPS; that is exactly what the reports are intended to establish.

## Bounded staged scanner (v0.5)

The earlier 136-endpoint × 44-service configuration could schedule **5,984 candidate-service combinations** before the first route existed. Each response could contain up to sixteen IPs. This overloaded a small VPS and delayed the first `proposed-plan.json`.

The default controller now runs four bounded phases:

1. **DNS prefilter:** one low-timeout DNS query per candidate, using the first mandatory domain, with no HTTP or API credential requests. The result is **not** service-availability evidence.
2. **Required:** pick up to 12 endpoints representing distinct DNS answers, keeping the existing active candidates and a reference where possible. Perform the full DNS→verified TLS→HTTP check on all required profiles, within 55 seconds.
3. **Preferred:** evaluate up to four promising endpoints against preferred profiles, within 75 seconds. If required coverage is missing, the optional phase is reduced to 12 seconds. A different provider can still be selected for an independently validated preferred service.
4. **Plan/report:** always write `service-report.json` and `proposed-plan.json` after a completed scan. A missing mandatory service means **no new plan is applied**. Routes lacking sufficient evidence remain unavailable.

Selection is deliberately **bounded, not exhaustive**: a non-selected provider is `NOT_SCANNED`, not proven broken. The scanner rotates distinct DNS-answer groups on later rounds and retains previously selected candidates. This trades immediate whole-catalogue coverage for availability and bounded resource usage. The first mandatory domain is the fast discriminator; providers that only serve a different mandatory domain may be discovered in a later, more specialized scan.

`config/manager.json` accepts:

```json
{
  "scan_strategy": {
    "required_candidates": 12,
    "preferred_candidates": 4,
    "dns_timeout": 1.5,
    "http_timeout": 2.5,
    "required_seconds": 55,
    "preferred_seconds": 75
  }
}
```

These are example fields **inside the full manager configuration**. Existing `local/manager.json` snapshots need not be overwritten: the manager supplies these defaults when omitted. Worker concurrency is capped at eight by the staged scanner, even if an older local configuration requests twelve.

Monitor the first cycle from the host:

```bash
cd /opt/ai-dns-manager/repo
cat local/service-state/scan-progress.json
ls -lh local/service-state/
docker logs --tail 30 ai-dns-manager
docker exec ai-dns-manager python -m ai_dns_manager.manager status --config /app/config/router.json --state-dir /state
```

The listener becoming `healthy` means only that it can answer a local UDP/TCP query. It is **not** a valid AI service plan. Before switching any VPN client, inspect `active-plan.json`, missing required services, actual failure classifications, and authenticated generation when that evidence is demanded.

Upgrading the existing installer creates a managed rollback container. It does not reconfigure AmneziaWG, the host resolver, public port 53 or other containers. Do not perform production DNS cutover based on the local listener healthcheck alone.

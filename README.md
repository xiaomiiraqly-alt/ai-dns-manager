# AI DNS Manager

[![Tests](https://github.com/xiaomiiraqly-alt/ai-dns-manager/actions/workflows/tests.yml/badge.svg)](https://github.com/xiaomiiraqly-alt/ai-dns-manager/actions/workflows/tests.yml)

**Experimental v0.6 — actual-generation-aware DNS selection for Linux, Docker and private VPN deployments.**

The original workflow is restored: discover providers → ask for actual DNS answers → check each selected AI service through those answers → rank by required/preferred coverage → select a primary and same-service reserves → verify again periodically. DNS availability alone is not an AI availability test.

## Gemini real-generation routing (v0.6)

A live deployment exposed a false positive: **Comss**, WebShift and ZombieDNS returned `AUTH_GATE` when checked with an invalid key, but authenticated Gemini generation returned `REGION_BLOCKED`. **DNS-AI** returned `GENERATION_OK` via `201.58.191.60` in the Karakeep network test.

The mandatory `gemini-api` service now requires **a successful authenticated model response**. An invalid-key gate, TLS handshake, or plausible Google IP can no longer make its route eligible. The required DNS candidate scan explicitly reserves space for allowed credentialed providers even when an old preferred plan contains many routes. Backups must also satisfy the same generation threshold.

The controller migrates previous `local/manager.json` configurations: Gemini becomes authorized for model checks, and the exact legacy reference-only credential policy switches to the demonstrated `dns-ai` provider. **No API key is fetched or generated.** Until valid credentials are securely mounted, Gemini fails closed rather than selecting Comss again.

To configure **one-time** encrypted provisioning of an existing Karakeep Gemini key and install from a pinned commit, follow [generation-aware deployment](docs/generation-routing.md). The installer automatically reuses `/etc/ai-dns-manager/gemini.env` on later upgrades. Provider queries run without credentials; model generation checks are restricted to the local trusted-provider allowlist and bounded per scan. Only the DNS-AI operator is trusted by the default example.

**No VPN clients or Karakeep DNS settings are modified by installing the manager.** The local DNS listener and real Gemini model use must both be verified from the intended network.

## VPS performance fix (v0.5)

The first service-aware scan is now **staged**, instead of immediately scheduling every provider × AI-service pair. The previously observed 136 DNS endpoints × 44 services would have required 5,984 service-level checks before a plan could be formed.

The new defaults use one short DNS prefilter per endpoint, up to **12** full tests per required service, and up to **4** providers for the remaining preferred services. Each deep phase has an independent time budget, with at most eight concurrent workers. A result not tested is `NOT_SCANNED`, not reported as broken. The result includes a `scan-progress.json` with `phase`, `required_ok`, `required_missing` and evaluation counts. No API key is needed to conduct the anonymous round.

**Running Docker container:** from the host read `local/service-state/scan-progress.json`; the container uses `/state`, not `/app/data/service-manager`. `healthy` still means only UDP/TCP listener health, not that AI routes exist. See [staged scanner design](docs/service-selection.md#bounded-staged-scanner-v05).

This intentionally trades exhaustive first-pass coverage for a bounded, rotating candidate frontier; provider coverage expands over repeated rounds. It does not prove that Gemini authenticated generation is regionally available.

## New service-aware mode

- **44 starter profiles**: web and API endpoints for text assistants, image/video/audio platforms, developer tools, aggregators and Russian services. Add an arbitrary public-domain service through JSON; the code is not limited to Gemini/ChatGPT/Claude.
- **Required / preferred / off** modes. A missing required service prevents a new plan from being applied. Preferred services influence ranking but do not override required ones. Disabled services are not probed.
- **Two kinds of route, two kinds of API check**: ordinary reference DNS versus Smart DNS; anonymous/fake-key checks versus explicitly authorized authenticated requests. Reference traffic still follows the machine's existing network/VPN.
- Verified DNS→TLS→HTTP checks detect regional refusals, bot challenges, authentication, quota, configuration and transport failures separately. HTTP 401 with a known invalid-key response is only `AUTH_GATE`, **not proof of generation**.
- Optional real text-generation checks use OpenAI-compatible or Anthropic adapters. A generic JSON adapter checks other authenticated APIs with an explicit success field. These are local trusted definitions, never downloaded from provider feeds.
- **Provider auto-update** from the same two source projects as the original: Mahiron-hq/ai-dns and WhIteGh0s1/DnsSwitch, with GitHub/jsDelivr sources, six-hour cache, stale-good fallback, validation, merging, exclusions and public-IP discovery. An imported address becomes a routing candidate, not an automatically trusted working route.
- **Per-service failover** with a sticky healthy route, consecutive-failure threshold and cooldown. Each backup must pass the same service's configured evidence threshold. An expired plan fails closed for monitored AI domains.
- Private DNS UDP/TCP service with UDP/TCP/DoH/DoT upstreams, local snapshots and rollback. **No host DNS/firewall/VPN edits.**

### What “support” means

The registry is extensible, not a claim that every neural network on the Internet has been tested. A web profile checks the entry page, not browser login, account access, WebSocket sessions or successful paid image/video/audio generation. Special API operations need a corresponding local probe definition and credentials. Several AI models behind the same API hostname use the same DNS route; their availability may still differ by account/model.

A domain cannot have two conflicting DNS policies based on HTTP paths. To test an API sharing its website's exact hostname, disable the overlapping web profile and supply a replacement custom profile at the desired evidence level. Separate web/API hostnames can be checked together.

## Run the new selector without applying anything

```bash
python3 -m ai_dns_manager.manager validate
python3 -m ai_dns_manager.manager scan --state-dir data/service-manager
```

Outputs: `catalogue.json`, `service-report.json`, `proposed-plan.json`. `scan` **does not activate** the plan. Default: Gemini API is required, other starter profiles preferred, no real API credentials used. Edit `config/manager.json` to preserve your own mandatory/desired set. [Full configuration and evidence guide](docs/service-selection.md).

To install the continuous service-aware pilot **after reviewing the plan** (Docker Engine only; Compose not needed):

```bash
python3 install.py install --service-aware
```

The daemon refreshes provider data when due and periodically rechecks services. It publishes only host loopback `127.0.0.1:5353`. It does not connect itself to all VPN clients, alter system DNS, disable IPv6 on the host or restart AmneziaWG. Its local healthcheck proves process/listener health only; inspect the service report for actual AI results.

**Privacy/cost:** real API tests are off by default. They need explicit service and DNS-provider allowlists plus local environment keys. Keys are never put into GitHub, provider feeds or JSON reports. Repeated generation checks may incur costs. See [security policy](SECURITY.md).

## Russian / Русский

Логика выбора теперь опирается на проверку самих AI-сервисов, а не только на ответ DNS. Обязательные и желательные сервисы сохранены. Успешный ответ с фиктивным ключом означает доступность точки входа, но не успешную генерацию. Для подтверждения генерации задайте `minimum_evidence: generation` и отдельно разрешите проверку с настоящим ключом.

Каталог содержит 44 начальных профиля и поддерживает свои домены без изменения Python-кода. Это не утверждение о проверенной работе всех перечисленных продуктов на вашем VPS. Для сайтов проверяется HTTP-доступность; для нестандартных API нужен собственный профиль проверки. Автообновление каталога не скачивает и не исполняет чужой код.

## First: read-only diagnostics

```bash
git clone https://github.com/xiaomiiraqly-alt/ai-dns-manager.git
cd ai-dns-manager
python3 -m unittest discover -s tests -v
python3 -m ai_dns_manager --config config/providers.json --output diagnostics.json
```

The candidate list includes ordinary baselines plus published DNS-AI and ZombieDNS endpoints. Candidates are **not endorsements**. Unlike the early prototype, DoH is `application/dns-message`, not a JSON-only interface. Bootstrap IPs are explicit so the forwarder never needs to resolve its own upstream through itself.

To opt into a small paid/quotable Gemini test, set `GEMINI_API_KEY` and `GEMINI_MODEL` **locally**, without committing them. `OPENAI_API_KEY` and `INFERENCE_TEXT_MODEL` are also accepted for an existing Karakeep environment.

```bash
python3 -m ai_dns_manager --gemini --max-api-probes 2 --output diagnostics.json
```

This sends at most two generation requests to distinct addresses that passed TLS verification. It does not save the key, response text, or original error body. Do not use unknown relays with sensitive content. No certificate checks can be disabled from configuration.

## Install a local pilot (Docker Engine, no Compose needed)

```bash
python3 install.py install
python3 install.py status
docker logs --tail=30 ai-dns-manager
```

This builds from the checked-out code and publishes **only `127.0.0.1:5353` UDP/TCP**. It does not edit `/etc/resolv.conf`, restart Docker, touch AmneziaWG or publish DNS on the public interface. The default router uses ordinary encrypted resolvers for both groups; it does **not** enable third-party Smart DNS silently.

The installer copies settings to `local/router.json` once and mounts a per-install snapshot. It refuses to replace unmanaged containers. On a failed replacement it attempts to restore the previous managed container. Explicit commands:

```bash
python3 install.py rollback
python3 install.py uninstall
```

A retained rollback snapshot is never silently deleted by a later update. [Deployment and update details](docs/deployment.md).

Compose is optional: `docker compose up -d --build`. Do not mix the Compose lifecycle with the Python installer's lifecycle for the same container name.

## Русский

Проект теперь содержит DNS-сервис, а не только TLS-проверку четырёх IP. Сначала выполняется настоящий DNS-запрос по UDP/TCP/DoH/DoT; затем проверяется сертификат по **адресу из ответа**, а не по адресу резолвера.

Для обычных и AI-доменов задаются отдельные группы. При сбое запрос повторяется через резерв внутри той же группы. Исправный резерв остаётся активным: нет постоянных скачков обратно на первый сервер. Монитор проверяет восстановление DNS. Работа Gemini с вашим ключом проверяется отдельно и только по явному `--gemini`.

Установка рассчитана и на серверы без `docker compose`. По умолчанию это локальный пилот на `127.0.0.1:5353`, **не DNS для всех VPN-клиентов**. Подключение клиентов и настройка маршрута до DNS — отдельная операция. Рабочий VPN не перенастраивается.

## Boundaries and licenses

No public recursive service, GUI, full browser automation, media-generation jobs, local DNSSEC validator, DoQ/HTTP3 or client-side cache/session reset. DoH currently uses HTTP/1.1. The IPv4-only service test cannot validate an alternative IPv6 path: service-aware forwarding suppresses AAAA/HTTPS/SVCB records **only for monitored domains**; other domains and host IPv6 configuration are unchanged.

Machine DNS settings and VPN routing still need an explicit deployment step. Shared or overlapping VPN subnets require careful forward/return routing; see [deployment](docs/deployment.md).

Implementation: MIT. The unmodified original provider DATA snapshot (`config/providers.seed.json`) is Apache-2.0, with original license and attribution in `third_party/mahiron/`. No original executable source was copied. Run offline tests with `python3 -m unittest discover -s tests -v`.

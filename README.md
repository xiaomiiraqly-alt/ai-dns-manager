# AI DNS Manager

[![Tests](https://github.com/xiaomiiraqly-alt/ai-dns-manager/actions/workflows/tests.yml/badge.svg)](https://github.com/xiaomiiraqly-alt/ai-dns-manager/actions/workflows/tests.yml)

**Experimental v0.3: private Linux DNS forwarding, encrypted upstreams, and read-only AI diagnostics.** Python 3.10+, standard library only. MIT licensed. Independent implementation, inspired by the workflow of [Mahiron-hq/ai-dns](https://github.com/Mahiron-hq/ai-dns); not a port of its Windows system modifications.

## What works

- UDP and TCP DNS listeners; UDP/TCP, authenticated DoT, and RFC 8484 binary-message DoH upstreams.
- Domain-suffix policy with longest-match selection. AI groups and ordinary traffic can use different upstreams.
- Sticky failover within a group, failure thresholds, cooldown, and periodic DNS recovery probes. No silent fallback from an AI group to a different group.
- Bounded concurrency, client-network ACLs, strict question/transaction matching, UDP-to-TCP fallback for truncated answers.
- Batch checks that first ask the resolver for the **actual target address**, then verify that target's TLS certificate.
- Optional authenticated Gemini generation check, distinguishing region refusal, credentials, quota, model problems and empty output. Keys are not stored in reports.
- Non-root read-only Docker image, loopback-only installer without Compose, configuration snapshots and rollback.

**A healthy DNS resolver or a valid certificate does not prove that Gemini works.** Automatic failover currently measures **DNS transport/response health**, not the availability of authenticated AI generation. HTTP API errors are reported by a separate, explicit probe and do not automatically rotate DNS. No claim of successful regional access is made.

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

## Boundaries

No public recursive service, UI, browser configuration, automatic provider-list downloading, DNS cache, DoQ/HTTP3, local DNSSEC validation, or automatic API-aware route selection in this version. DoH uses HTTP/1.1. IPv4 listener; IPv4 and IPv6 upstream literals supported. Existing application DNS caches/connections are not forcibly reset. The DNS monitor does not claim to detect service-specific region refusals.

See [provider sources](docs/providers.md), [security policy](SECURITY.md), and [changelog](CHANGELOG.md). Run offline tests with `python3 -m unittest discover -s tests -v`.

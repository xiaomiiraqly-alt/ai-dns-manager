# AI DNS Manager

Linux-first diagnostics and (planned) policy-based DNS routing for AI services, designed for Docker and VPN deployments.

> **Status: early prototype.** This release performs **read-only diagnostics only**. It does not install a DNS server, modify routes, change resolv.conf, or configure AmneziaWG.

## Quick start

Requires Python 3.10+; no third-party Python dependencies.

```bash
git clone https://github.com/xiaomiiraqly-alt/ai-dns-manager.git
cd ai-dns-manager
python3 -m ai_dns_manager --config config/providers.json --output diagnostics.json
```

Optional: `python3 -m unittest discover -s tests -v`

The tool checks DNS answers over UDP/53, then attempts a verified TLS connection to the target hostname using each returned IPv4 address. **A valid TLS connection does not establish that a paid or region-restricted AI API is usable.** No API credentials are transmitted.

## Security

* Never disable TLS certificate verification to make a provider appear healthy.
* A Smart DNS answer may direct traffic to a third-party relay; evaluate the provider's trust and privacy before using it with credentials.
* DNS failures, TLS failures, and API authorization/region errors are distinct conditions.
* Do not expose a recursive resolver on a public interface.
* Respect each AI provider's terms and geographic availability requirements.

## Roadmap

1. Read-only DNS and TLS diagnostics (initial implementation).
2. Configurable DoH/DoT checks and per-provider service discovery.
3. Local, domain-scoped DNS forwarder with explicit opt-in.
4. Health-based failover with hysteresis, audit log, and rollback.
5. Docker packaging and optional AmneziaWG integration.

## Русский

Проект для диагностики DNS и сетевой доступности AI-сервисов на Linux. Текущая версия **не меняет настройки DNS/VPN**. Для запуска достаточно Python 3.10+. Параметры проверок находятся в `config/providers.json`. Не используйте сторонние Smart DNS для запросов с ключами API без оценки доверия к оператору.

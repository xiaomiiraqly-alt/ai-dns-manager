# AI DNS Manager

[![Tests](https://github.com/xiaomiiraqly-alt/ai-dns-manager/actions/workflows/tests.yml/badge.svg)](https://github.com/xiaomiiraqly-alt/ai-dns-manager/actions/workflows/tests.yml)

**Experimental Linux DNS and TLS diagnostic tool.** Designed for Docker/VPN environments, including AmneziaWG. Current version is **read-only**: no DNS server, failover, routing changes or VPN integration yet.

## Quick start (Ubuntu)

Python 3.10+ is required. No third-party Python dependencies.

```bash
git clone https://github.com/xiaomiiraqly-alt/ai-dns-manager.git
cd ai-dns-manager
python3 -m ai_dns_manager --config config/providers.json --output diagnostics.json
python3 -m unittest discover -s tests -v
```

Or use Docker without changing the host network:

```bash
docker build -t ai-dns-manager:dev .
docker run --rm --network bridge --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  ai-dns-manager:dev
```

The container prints diagnostics to stdout. To save a report, mount a writable directory and specify `--output /reports/diagnostics.json`.

## What the tests mean

For each configured DNS server, the program performs a UDP/53 A-record lookup for the target domain and verifies TLS against returned addresses (up to four). It does **not** use API credentials and cannot confirm API functionality or regional eligibility. A DNS timeout does not imply a DoH or DoT endpoint is unavailable. The default IPs are **unverified candidates, not endorsed providers**.

Never disable TLS verification to force a passing test. A Smart DNS may route HTTPS to a third-party relay; review its operator and security before sending API credentials. Respect API provider geographic restrictions and terms.

## Русский

Экспериментальный инструмент диагностики DNS и TLS для Linux. Сейчас только проверяет доступность, **не меняет** DNS, маршруты или конфигурацию VPN. Примеры адресов в `config/providers.json` не являются рекомендациями. Отказ API по региону нельзя автоматически считать неисправностью DNS.

## Roadmap

- [x] DNS UDP/53 and TLS diagnostics; JSON reports
- [x] Dockerfile, CI tests and license
- [ ] DoH/DoT diagnostics and configurable provider metadata
- [ ] DNS forwarding service with per-domain policy and explicit opt-in
- [ ] Health-based failover, hysteresis and audit log
- [ ] Optional integration with AmneziaWG without exposing port 53 publicly

## License

MIT.

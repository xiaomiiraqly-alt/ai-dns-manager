# Deployment — opt-in local DNS forwarder

**Experimental. Do not configure as the default VPN DNS until you have verified correct answers and safe fallback.**

Requirements: Docker Engine and the Docker Compose plugin. On Ubuntu 24.04, `docker compose version` must work. No other container is modified.

```bash
git clone https://github.com/xiaomiiraqly-alt/ai-dns-manager.git
cd ai-dns-manager
docker compose build
docker compose up -d
docker compose logs --tail=50
```

The service listens **only on host loopback** `127.0.0.1:5353` for UDP and TCP. It does not expose port 53 or join the AmneziaWG network.

To test from the host:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig +tcp @127.0.0.1 -p 5353 example.com A
```

To stop and remove it without affecting other Docker services:

```bash
docker compose down
```

## Policy

`config/router.json` contains two upstream groups. The shipped example uses ordinary DNS resolvers for **both** groups. It does not route through third-party Smart DNS relays. Edit rules only after evaluating providers and their terms. Failover applies to network timeouts and upstream SERVFAIL, not HTTP API authorization/region errors.

Changes to a running config require recreating this service (`docker compose up -d --force-recreate`); no host-level DNS settings are changed.

## Limitations

- UDP/TCP DNS forwarding only, not yet DoH/DoT forwarding.
- Basic cooldown-based failover, not a background health checker.
- No cache, persistent audit log, UI, or auto-updater.
- Not intended to be a public recursive resolver.
- DNS response validation is minimal; avoid untrusted upstreams.
- Avoid enabling this service for VPN clients until routing and access-control tests are complete.

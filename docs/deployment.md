# Deployment / Установка

## Local pilot first

Requirements: Linux, Python 3.10+, Docker Engine, a user permitted to use Docker. Compose is optional. Pin a reviewed commit before installation. Do not run a remote shell script piped into root.

If `/opt/ai-dns-manager` already contains diagnostic files, clone into a separate subdirectory, not over them:

```bash
git clone https://github.com/xiaomiiraqly-alt/ai-dns-manager.git /opt/ai-dns-manager/repo
cd /opt/ai-dns-manager/repo
python3 -m unittest discover -s tests -v
python3 -m ai_dns_manager --output diagnostics.json
python3 install.py install
```

The first diagnostic makes outbound DNS/TLS connections but changes no configuration. The installer builds an image, validates configuration with networking disabled, and creates only its own container. It publishes UDP/TCP on **host loopback port 5353**, not public port 53. The container runs as UID/GID 65534, read-only, without Linux capabilities or Docker-socket access.

## Configuration and Smart DNS opt-in

`config/providers.json` is the diagnostic candidate list. `config/router.json` is a conservative server example. `config/router.smartdns.example.json` is an **opt-in**, unvalidated-for-your-network Smart DNS example; never assume that a successful DNS/TLS probe proves Gemini generation.

Each upstream has `name`, `protocol` (`udp`, `tcp`, `doh`, `dot`) and a numeric `ip` or `bootstrap_ip`. DoH also needs `url`, DoT needs `hostname`. Ports may be set for UDP/TCP/DoT; a DoH URL contains its port. TLS certificate verification is mandatory. No URL credentials, redirects or proxy environment variables are used by DNS transports.

`groups` are ordered choices at startup. `rules` use DNS suffix boundaries, most specific first. When the active upstream fails, a query may try the next member within its time budget. Repeated failures trigger cooldown; background probes require consecutive successes to clear a failed state. A working backup is sticky, not immediately replaced by a recovered primary. No answers are cached locally. If the entire selected group is down, return SERVFAIL instead of leaking the query into another group.

`allowed_clients` is an explicit CIDR allowlist. The supplied local-Docker config permits loopback and Docker-style 172.16.0.0/12 networks; narrow it for your deployment. Do not bind a recursive DNS service to the Internet. `max_workers` limits simultaneous client work across UDP and TCP. Monitoring uses at most four additional workers.

`health.ai-dns-manager.invalid` checks the local listener without upstream traffic. Its success means the process can serve DNS over UDP/TCP, **not** that AI APIs are usable. `docker logs` contains structured failures, switches and periodic health summaries, not client queries or API keys. Installer/Compose configure bounded Docker log rotation.

## Updates and rollback

1. Fetch and check out a reviewed commit; do not blindly pull unreviewed code into production.
2. Edit `local/router.json` or supply `--config /absolute/path.json`.
3. Run `python3 install.py install` again. A previous managed container is retained as `ai-dns-manager-rollback`; its original image and mounted config snapshot stay intact.
4. On failure, the installer attempts to restore that old container. Verify status and logs; do not treat an attempted rollback as proof of successful recovery.
5. `python3 install.py rollback` explicitly restores the snapshot. A second update refuses to overwrite an existing rollback snapshot. After accepting the current version, an administrator may remove that named snapshot manually.

`python3 install.py uninstall` removes only containers with this installer's ownership label. It leaves images/configuration files and other applications alone. Compose-created containers use a separate lifecycle; the installer will refuse to replace them. The repo does not contain API keys, VPN profiles or private server configuration.

## AmneziaWG: integration is not automatic

Do not replace the host's systemd-resolved configuration or restart the VPN just to test this service. A service in a Docker bridge is not automatically reachable from VPN clients. Both forward and return paths, NAT/firewall policy, UDP **and** TCP 53, and client DNS settings need validation.

For a production design, the DNS endpoint should be on a private reachable service address, not the public VPS address. If a container listens on port 53 as non-root, set the per-container unprivileged-port sysctl explicitly; do not grant privileged mode or alter the host sysctl as a shortcut.

**Multi-hop warning:** if ingress and egress AWG servers both use the same tunnel prefix, a DNS address from that prefix may resolve to the wrong end. Choose a non-overlapping service subnet and an explicit route, with a valid return path. A router that excludes RFC1918 destinations from its outbound tunnel also needs an explicit service route. Setting a DNS address in the client alone is insufficient.

The supplied installer intentionally does not perform any of those mutations. Validate one test client before changing the rest. Client-side DoH, cached answers, existing TLS connections and IPv6 can bypass a DNS-only policy and must be tested separately.

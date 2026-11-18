# Karakeep split DNS without restarting the AWG tunnel

The outbound egress VPS hosts **AI DNS Manager** and (since v0.7) a private DNS gateway on the actual WireGuard address (`10.8.1.1:53` only when that address was reported by the gateway installer).

The Karakeep VPS has a separate `karakeep-awg-client`. Its `karakeep-web-1` and `karakeep-chrome-1` containers share that client's network namespace. They may need Docker's internal DNS resolver for names such as `meilisearch`. Replacing their DNS with the remote AWG address unconditionally could break ordinary Docker service discovery.

`scripts/karakeep_split_dns.py` installs an isolated DNS sidecar **inside the existing AWG client's network namespace**, listening only on `127.0.0.53:53`. The sidecar forwards:

- **required** AI services, including Gemini, exclusively to the egress AWG private DNS server, with no direct-DNS fallback;
- **preferred** AI services first to the private DNS server, and then to the original resolver if the remote service route yields a DNS transport error/SERVFAIL;
- **ordinary domains and Docker service names** to the original container resolvers, preserving their original order, `search` and `options` entries.

The installer changes the Docker-managed `resolv.conf` files **in-place** for the two selected running Karakeep containers only, after the remote gateway and local sidecar have answered DNS queries. It does not restart/recreate any Karakeep container, modify Compose, change the host's resolver, alter iptables/nftables or restart AmneziaWG. No API keys are transferred; the egress AI DNS Manager already holds its own approved credentials.

## Enable

Run first on the **egress** VPS:

```bash
cd /opt/ai-dns-manager/repo
git fetch origin main
git checkout --detach origin/main
python3 scripts/awg_dns_gateway.py install
```

The gateway must print `PRIVATE DNS READY at ...:53`. It refuses to activate without a recent applied, real `GENERATION_OK` Gemini route.

Then on **Karakeep** VPS (VM-982026):

```bash
git clone https://github.com/xiaomiiraqly-alt/ai-dns-manager.git /opt/ai-dns-karakeep
cd /opt/ai-dns-karakeep
python3 scripts/karakeep_split_dns.py install --gateway 10.8.1.1
```

Use the exact private IP printed by the egress command rather than 10.8.1.1 if the AWG subnet differs. The client installer automatically checks that the egress gateway can answer Gemini and that the ordinary resolver can answer through the sidecar. If either is unavailable, it leaves the original Karakeep DNS files untouched.

The installer requires root access to Docker's per-container `resolv.conf` files and to inspect the shared network namespace. It **does not** access or change the AWG profile, original Karakeep application image, data volume or database.

## Status and rollback

On Karakeep:

```bash
cd /opt/ai-dns-karakeep
python3 scripts/karakeep_split_dns.py status
python3 scripts/karakeep_split_dns.py uninstall
```

A private manifest `local/karakeep-split-dns/manifest.json` records original DNS file contents and the affected container IDs. Uninstall restores each file before removing the owned sidecar; it refuses to overwrite files that were changed by somebody else.

On egress the independent gateway can be removed with:

```bash
python3 scripts/awg_dns_gateway.py uninstall
```

Restore Karakeep's resolver first, then remove the egress gateway. Running AWG and existing peer connectivity remain unchanged throughout.

## Important persistence limitation

Docker owns and can recreate its `resolv.conf` files when a container is replaced/restarted. This installer deliberately performs **live, zero-recreation activation**, not an unsupported permanent modification of Compose. If Karakeep web/Chrome/AWG containers are recreated, their resolver settings may revert, and the sidecar may become disconnected from a newly created AWG network namespace. Run the installer again after inspecting/reconciling the old manifest, or implement a dedicated reviewed Compose-level persistent DNS configuration. Do not mistake this runtime integration for permanent configuration management.

AI availability still depends on the manager's fresh generation proof and on existing client networking. Applications using built-in DoH or fixed IPs can bypass the system resolver. This installer does not intercept connections to arbitrary DNS ports.

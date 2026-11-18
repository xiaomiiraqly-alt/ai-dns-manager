# Private AmneziaWG DNS gateway (egress VPS)

## What this enables

AI DNS Manager already runs at `127.0.0.1:5353` on the egress VPS. That is **not reachable by AmneziaWG peers**. This gateway connects its Docker container to the existing private `amnezia-dns-net` bridge and creates a very small DNS UDP/TCP forwarder **inside the existing AWG network namespace**. It binds only the AWG interface address (`awg0`, typically `10.8.1.1:53`), not the VPS public interface and not the host's resolver.

The normal DNS manager continues selecting DNS providers according to mandatory authenticated Gemini generation and optional service reachability. The gateway does not choose providers; it delegates to the manager. The manager's public egress default gateway is explicitly preserved with Docker network `--gw-priority -1`. Consult Docker's `network connect` documentation if using a different Docker version.

**No system-wide DNS, iptables/nftables, AmneziaWG peer configuration, client policy, kernel sysctl or firewall configuration is changed by this installer.** It requires no Docker Compose plugin.

## Enable the private server-side gateway

On the egress VPS (`root@amnezia`):

```bash
cd /opt/ai-dns-manager/repo
git fetch origin main
git checkout --detach origin/main
python3 scripts/awg_dns_gateway.py install
```

This is an operational action, not another diagnostic suite. It reads the existing containers `amnezia-awg2` and `ai-dns-manager`, determines the WG IPv4 address, connects the latter to the existing Docker bridge, and creates `ai-dns-awg-gateway`. It will **not activate if an applied Gemini route has not proved real `GENERATION_OK` in the last 30 minutes**. This is intentional to avoid sending peers to a fake-key `AUTH_GATE` route.

Successful output includes `PRIVATE DNS READY at <wg-ip>:53 (UDP/TCP)`. This verifies the new gateway listener and its local handling, not every remote API or end-user browser.

The gateway listens on the **VPN server's private tunnel address only**. Docker publishes no public DNS port. Port 53 in the shared AWG network namespace must be unused; if something already binds there, the installer stops and does not replace it.

## Actually use it from clients

**WireGuard does not push DNS settings from server to peers.** For a peer whose tunnel includes the AWG interface address, set the DNS server in the client's Amnezia/WireGuard profile to the private WG gateway address reported by the installer, generally:

```ini
DNS = 10.8.1.1
```

This example is only valid if the installer printed `10.8.1.1` for the configured AWG interface. The tunnel must route packets to that address. For split routes, make sure the server's WG address is in the peer's permitted destinations. Browser DoH and applications with hard-coded resolvers can bypass this DNS policy and are not reconfigured.

**For Karakeep specifically**, the server-side gateway alone does not change its Docker/Chrome DNS configuration, and does not automatically redirect the application's traffic to it. Karakeep's DNS setting and its separate AWG client routing must be updated in its own deployment. Do not restart or recreate unrelated Karakeep containers without confirming their network routes and retained data.

The gateway uses its own ACL derived from the `awg0` private subnet; requests from other sources are rejected. Do not add a host `0.0.0.0:53` binding or publish `53:53` ports.

## Backout, upgrade and limitations

To disable only this new DNS listener:

```bash
cd /opt/ai-dns-manager/repo
python3 scripts/awg_dns_gateway.py uninstall
```

It removes only the owned `ai-dns-awg-gateway` sidecar, leaving the AWG container, main DNS manager and peer settings intact. Revert any peer DNS profile change separately to its previous value.

A main manager image replacement can allocate a new private bridge address. This gateway detects a mismatch and refuses to report a stale gateway as ready. If replacing the manager, remove the gateway first (or after a failed detection) and reinstall it after the updated manager has a valid generation plan. The gateway also shares the AWG container's network namespace: if AWG itself is replaced, recreate this sidecar.

This solution does **not** perform transparent interception of all port-53 traffic or forcibly change VPN client DNS. It cannot guarantee that clients using their own DoH or their own fixed DNS will use AI DNS Manager. Do not mistake the existence of `ai-dns-awg-gateway` for deployment to every peer. The two-VPS Karakeep topology may have additional private-address routing exclusions; adjust the intended peer's DNS path, not the entire host or VPN blindly.

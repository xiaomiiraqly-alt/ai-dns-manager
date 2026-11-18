# Generation-aware Gemini routing and minimal deployment (v0.6)

## Why the previous "healthy" plan was wrong

On 2026-11-18, the private DNS forwarder had selected Comss for the required Gemini API based on an `AUTH_GATE` response from a deliberately invalid key. Direct authenticated generation from the Karakeep network produced these outcomes:

| DNS answer provider | Sample Gemini IPv4 | Actual authenticated result |
| --- | --- | --- |
| Comss | 142.251.150.2 | REGION_BLOCKED |
| DNS-AI | 201.58.191.60 | GENERATION_OK |
| WebShift | 31.31.207.68 | REGION_BLOCKED |
| ZombieDNS | 186.243.168.31 | REGION_BLOCKED |

This result is **specific to that test's source network, account, model and time**. It does not prove that any of these providers always works or that the direct egress VPS follows the same path. Routing must therefore be validated on the actual destination network.

v0.6 changes `gemini-api` to `required + generation`. The manager now requires an authenticated, nonempty Gemini model output, not a DNS answer or fake-key gate. It selects the best verified provider for that exact service; all backups must satisfy the same evidence requirement. Without a key/model or if generation is region-blocked, **no new required-service plan is activated**. Older active plans from v0.5 cannot be loaded silently because the policy and authorization requirements changed.

## One-time credential provisioning from Karakeep

The existing key and model reside in `karakeep-web-1` on the Karakeep VPS. This **optional operator-controlled procedure copies those secrets over an authenticated SSH connection to the DNS egress VPS**. That expands who can access the key to administrators of the egress server and Docker daemon. Do not run it if that trust decision is unacceptable. The alternative is a future remote proof agent that never transfers the secret; it is **not** implemented here.

Run this block **on the Karakeep host**, not inside its container. It does not display the key or model to the terminal. Inspect the SSH host-key prompt before accepting a new server. Replace the SSH destination only if your VPS address changed.

```bash
set -Eeuo pipefail

DEST='root@31.57.157.93'

docker exec karakeep-web-1 node -e '
const env = process.env;
const key = env.GEMINI_API_KEY || env.OPENAI_API_KEY;
const model = env.GEMINI_MODEL || env.INFERENCE_TEXT_MODEL;
if (!key || !model || /[\r\n\0]/.test(key + model)
    || !/^[a-zA-Z0-9._\/:-]+$/.test(model)) {
  process.stderr.write("A usable Gemini key/model pair is unavailable in Karakeep.\n");
  process.exit(2);
}
process.stdout.write("GEMINI_API_KEY=" + key + "\nGEMINI_MODEL=" + model + "\n");
' | ssh "$DEST" '
set -eu
umask 077
install -d -m 700 /etc/ai-dns-manager
tmp=$(mktemp /etc/ai-dns-manager/.gemini.env.XXXXXX)
trap '"'"'rm -f "$tmp"'"'"' EXIT
cat > "$tmp"
grep -q "^GEMINI_API_KEY=." "$tmp"
grep -q "^GEMINI_MODEL=." "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" /etc/ai-dns-manager/gemini.env
trap - EXIT
echo "Private Gemini credential file provisioned on egress VPS"
'
```

The manager never uploads the key to GitHub, embeds it in a report, or sends it to a provider without verified HTTPS hostname/certificate identity. Only explicitly allowed provider IDs can be used for credentialed probes. The default approved candidate is `dns-ai`; additional operators require an explicit local trust-list change. An authenticated probe may incur API charges. Review both VPS and connected Docker administrators as key custodians.

## Upgrade the running egress VPS

On the **egress VPS** (`amnezia`):

```bash
cd /opt/ai-dns-manager/repo
git fetch origin main
git checkout --detach origin/main
python3 install.py install --service-aware --archive-rollback
```

The installer checks for the private `/etc/ai-dns-manager/gemini.env` file and mounts it as an environment file on each service-aware install or update. It validates mode 0600 or stricter and that the accepted variables match trusted local service profiles. The old managed container becomes the current rollback, and an earlier rollback is retained under a timestamped name rather than deleted. The installer changes no AmneziaWG, host DNS, firewall rules or clients.

If credentials are absent, installation still creates a healthy local DNS listener for inspection, **but mandatory Gemini will fail closed**. Listener health is not generation health.

## Observe automatically selected results

```bash
cd /opt/ai-dns-manager/repo
cat local/service-state/scan-progress.json
python3 - <<'PY'
import json
from pathlib import Path
p=Path('local/service-state/active-plan.json')
if not p.is_file():
    print('NO_VALID_GENERATION_PLAN')
else:
    plan=json.loads(p.read_text())
    for route in plan.get('routes',[]):
        if route['service']=='gemini-api':
            print('Gemini:',route.get('provider_id'),route.get('status'),
                  'evidence:',route.get('evidence'),'backups:',len(route.get('backups',[])))
PY
```

A legitimate new plan has `gemini-api` with `status=GENERATION_OK` and `evidence=4`. A missing active plan, `KEY_MISSING`, `REGION_BLOCKED`, or `PROBE_NOT_AUTHORIZED` is not a success. The log may indicate DNS prefilter and scan progress, but no plaintext key or response content.

To add other trusted candidates for automatic generation failover, edit `local/manager.json`'s `credential_provider_ids` list, such as `dns-ai`, `geohide-us` or another vetted source. A provider does **not** become a backup just because it resolves the hostname: it must pass its own real authenticated generation check. This is a security choice, not an automatic provider list import.

**Important network boundary:** the local DNS port `127.0.0.1:5353` on the egress VPS is not currently the DNS server of Karakeep or all VPN clients. Until that connectivity, split-DNS policy and IPv4/IPv6 routes are set up and verified for one test client, an active manager plan does not automatically make existing applications use it.

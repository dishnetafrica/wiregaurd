# DishNet Secure Connect — Phase 1: Findings, Architecture and Proposed Changes

Status: **proposal for review — nothing has been implemented or deployed yet.**
Date: 2026-10-02

---

## 1. Findings

### 1.1 Repository

`dishnetafrica/wiregaurd` is empty: no commits on any branch, no files, no
existing stack or conventions to reuse. Everything below is a greenfield
choice, made to suit a 1-vCPU / $4 Droplet and a small team.

### 1.2 Server (165.227.89.92)

The Droplet could **not** be inspected from this session: outbound SSH to
165.227.89.92:22 is blocked by the sandbox network policy and no SSH
credentials are present. The infrastructure facts in this document are taken
from the brief, not verified. Before Phase 2 touches the server I need the
output of the commands in §7 (secrets redacted), or SSH access.

Known from the brief:

| Item | Value |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Interface / port | `wg0`, UDP 51820 |
| Subnet / hub address | `10.20.0.0/24`, hub `10.20.0.1` |
| Server public key | `UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs=` |
| Config / keys | `/etc/wireguard/wg0.conf`, `server_private.key`, `server_public.key` |
| Service | `wg-quick@wg0` |
| Peers | none |
| IPv4 forwarding | enabled |
| Forwarding policy | "broad wg0-to-wg0" rule (assumed `iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT` in `PostUp`) |

### 1.3 Security risks in the current hub configuration

| # | Risk | Impact | Fix (Phase 2) |
|---|---|---|---|
| R1 | `FORWARD -i wg0 -o wg0 ACCEPT` | Any peer reaches any other peer: customer A can scan customer B's server. Fatal for a multi-tenant service. | Replace with an nftables table owned by the management service: `forward` chain policy **drop**, explicit per-device accept rules, conntrack for return traffic. |
| R2 | No FORWARD policy for `wg0 → eth0` stated | If a client's `AllowedIPs` were ever `0.0.0.0/0`, the hub becomes an open internet proxy (bandwidth cost, abuse). | Default drop; the server never pushes `0.0.0.0/0`; no MASQUERADE rule unless Mode B explicitly needs it. |
| R3 | Peers managed by hand-editing `wg0.conf` | Not atomic; a half-written file on `wg-quick` restart drops every customer; private key sits next to the config. | Management service owns peers via netlink (`wgctrl`), persists them in its own DB, and reconciles on boot. `wg0.conf` keeps only `[Interface]`. |
| R4 | FORWARD rules in `PostUp/PostDown` | Rules disappear/duplicate on every `wg-quick` restart; nothing reconciles. | Firewall state lives in an nftables table applied idempotently (`nft -f` of a generated file, flush-table + rebuild atomically). |
| R5 | Flat `/24` with no per-tenant structure | Nothing in the address plan prevents cross-tenant traffic; isolation would rest on firewall rules alone. | Per-customer `/29` blocks carved from `10.20.0.0/24` (pilot) + firewall. See §3.4. |
| R6 | SSH exposure, DO Cloud Firewall, ufw state unknown | Possible open management ports. | Audit (§7) before adding the HTTPS API; restrict SSH by DO Cloud Firewall to admin IPs. |
| R7 | Office servers behind Starlink CGNAT | They cannot accept inbound connections; the office server must itself be a VPN peer. This changes the architecture (§3.3) and the current config does not model it. | Two peer roles: `client` and `server/gateway`. |

---

## 2. Technology decisions

| Component | Choice | Why |
|---|---|---|
| Management API + admin dashboard | **Go 1.22+**, single static binary (`dishnet-vpnd`), `net/http` + `html/template`, **SQLite** (`modernc.org/sqlite`, pure Go) | One binary, ~30 MB RAM — fits the $4 Droplet. No runtime to install. `golang.zx2c4.com/wireguard/wgctrl` manages peers through netlink (no shell-outs). SQLite is enough for hundreds of customers and is trivial to back up. |
| Firewall control | nftables, rules generated from DB into `/etc/nftables.d/dishnet.nft`, applied with `nft -f` (fixed path, no client-supplied strings) | Atomic table replacement; one source of truth; survives restarts. |
| Privilege model | `dishnet-vpnd` runs as a dedicated user with `CAP_NET_ADMIN` only (systemd `AmbientCapabilities`), never root; it cannot read `server_private.key` | Least privilege. The API process has no shell and no access to the hub private key. |
| TLS | Caddy in front (automatic Let's Encrypt) **or** Go `autocert`; needs a DNS name (e.g. `vpn.dishnet.africa`) | Required for HTTPS to the API and dashboard. |
| Windows client | **C# / .NET 8, WPF**, self-contained publish, **Inno Setup** installer (`DishNetSecureConnect-Setup.exe`) | WPF is mature, works on Win10/11 and Windows Server (WinUI 3 does not target Windows Server reliably). Inno Setup handles UAC, upgrade and uninstall well and is free. |
| Tunnel engine | Official **WireGuard embeddable-DLL service** (`tunnel.dll` + `wireguard.dll` from wireguard-windows / wireguard-nt), used exactly as in the upstream `embeddable-dll-service` example | No crypto or protocol implemented by us. The installer registers a Windows service `DishNetTunnel$office` that loads `tunnel.dll`. Upgrade/uninstall = stop + delete service. |
| Device key storage | Generated on the device with `wireguard.dll`'s key API; stored with **DPAPI (LocalMachine scope)** in `%ProgramData%\DishNet\`; only the public key is sent to the API | Private key never leaves the device, never appears in logs or API traffic. |

### Licensing / redistribution (to verify in Phase 5, flagged now)

* `wireguard-windows`, `tunnel.dll`, `wireguard.dll` and the `wireguard-nt`
  driver are MIT-licensed; redistribution with attribution is permitted.
* **"WireGuard" is a registered trademark of Jason A. Donenfeld.** The product
  must be branded "DishNet Secure Connect" and may only say "powered by
  WireGuard®" in accordance with the WireGuard trademark policy. The installer
  must not name itself or its services "WireGuard".
* The signed `wireguard-nt` kernel driver is distributed inside `wireguard.dll`;
  we do not need our own driver signature. Our own `.exe`/`.dll`/installer
  still need an Authenticode certificate (OV ≈ US$200–400/yr; EV avoids
  SmartScreen warnings immediately but costs more and needs a hardware token).

---

## 3. Architecture

### 3.1 Components

```
 Customer PC (Windows)                 DigitalOcean hub 165.227.89.92             Customer office
┌──────────────────────┐              ┌────────────────────────────────┐        ┌─────────────────┐
│ DishNet Secure       │  HTTPS 443   │ Caddy (TLS)                    │        │ Office server   │
│ Connect (WPF)        │─────────────▶│   └─ dishnet-vpnd  (Go)        │        │ (Tally/ERP/RDP) │
│   ├─ activation      │              │        ├─ SQLite  /var/lib/...  │        │ runs the same   │
│   ├─ status / logs   │              │        ├─ wgctrl → wg0 (netlink)│        │ client in       │
│   └─ service control │              │        └─ nft  → table dishnet  │        │ "server" role   │
│ DishNetTunnel$office │  UDP 51820   │ wg0  10.20.0.1/24              │ UDP    │ 10.20.0.11      │
│ (tunnel.dll service) │◀════════════▶│ FORWARD policy: drop,          │◀══════▶│ keepalive 25s   │
│ 10.20.0.10           │  WireGuard   │ per-device accept rules        │        │ (CGNAT-safe)    │
└──────────────────────┘              └────────────────────────────────┘        └─────────────────┘
                                         ▲ HTTPS (admin, MFA, IP-restricted)
                                         │ Admin dashboard: customers, codes, devices, audit
```

### 3.2 Peer roles

Because office servers sit behind Starlink CGNAT, **the office server is also
a peer** and dials out to the hub. A customer therefore has:

* **Server/gateway peers** — the office PC/server (Mode A) or an office router
  / Linux box (Mode B, with its LAN subnet in `AllowedIPs`).
* **Client peers** — staff laptops.

All traffic is hairpinned on the hub (`wg0 → wg0`) under explicit rules. This
is the only way remote access works without port-forwarding at the office.

### 3.3 Access modes

**Mode A — server-only (default).** The client receives:

```
[Interface] Address = <device /32>; DNS = (none)
[Peer] PublicKey = hub; Endpoint = 165.227.89.92:51820
       AllowedIPs = <office server VPN IP>/32        # split tunnel, nothing else
       PersistentKeepalive = 25
```

Hub firewall: `src <client ip> → dst <server ip> tcp dport {3389, 9000}` (ports
per policy) accept; established/related accept; everything else drop.

**Mode B — site-to-site.** Gateway peer `AllowedIPs = <gw ip>/32, <office LAN>/24`;
client `AllowedIPs = <office LAN>/24`. Hub forward rules `src client → dst LAN`
limited to the ports in the policy. Overlap of LAN subnets across customers is
rejected by the API at policy creation (and against `10.20.0.0/24`,
`10.0.0.0/8` defaults flagged with a warning).

**Tally.** Tally's data files are opened directly by `tally.exe`; serving them
over SMB across a Starlink link is slow and corrupts data on disconnect. The
recommended policy template for Tally customers is **RDP (3389) to the office
server** or **Tally's own client/server port (9000)** — never SMB/445. SMB is
blocked by default in every policy template and must be enabled explicitly
with a warning.

### 3.4 Addressing and isolation

* Pilot: keep `10.20.0.0/24`. Allocate each customer a **/29** (8 addresses:
  1 reserved, up to 6 peers; 30 customer blocks). `10.20.0.0/29` is reserved
  for the hub.
* Growth: add `10.21.0.0/16` as a second pool; the allocator is pool-aware.
  The existing subnet is never changed.
* Isolation is enforced **twice**: (1) nftables default-drop forward chain
  with per-device rules, (2) each peer's server-side `AllowedIPs` is exactly
  its assigned /32 (+ LAN for gateways), so a device cannot spoof another
  address — WireGuard drops packets whose source is not in the peer's
  `AllowedIPs` (cryptokey routing).
* The hub never adds `0.0.0.0/0` and has no NAT rule unless a Mode B policy
  explicitly requires it.

### 3.5 Data model (SQLite)

```
customers        id, name, contact, status(active|suspended), subscription_expires_at,
                 device_limit, vpn_block (cidr /29), created_at
activation_codes id, customer_id, code_hash (argon2id), role(client|gateway),
                 max_uses, uses, expires_at, revoked_at, created_by, created_at
devices          id, customer_id, name, role, public_key (unique), vpn_ip (unique),
                 lan_subnets (gateway only, json), status(active|revoked),
                 last_handshake_at, rx_bytes, tx_bytes, device_token_hash,
                 registered_at, revoked_at, revoked_reason
access_policies  id, customer_id, from_device_id|null(any client), to_device_id,
                 to_cidr|null, proto, ports (json), enabled
provisioning_jobs id, device_id, action(add|remove|update), state(pending|applied|failed),
                 error, attempts, created_at, applied_at
admins           id, email, password_hash, role(owner|operator|viewer), totp_secret, created_at
audit_log        id, at, actor_type(admin|device|system), actor_id, action, target, detail(json), ip
api_rate_limits  (in-memory, keyed by IP + code prefix)
```

### 3.6 API contract (v1)

Public (device-facing), JSON over HTTPS, rate-limited (5 activation attempts /
IP / 10 min; exponential lock-out per code):

| Method | Path | Body → Response |
|---|---|---|
| `POST` | `/api/v1/activate` | `{code, public_key, device_name, os, client_version}` → `{device_id, device_token, vpn_ip, server_public_key, endpoint, allowed_ips[], keepalive, dns[], policy_summary}`. Single-use (or `max_uses`) enforced in one SQLite transaction with the IP allocation — no races. |
| `GET` | `/api/v1/device/config` | Bearer `device_token` → same config object (for reconnect / rotation). Returns `403 {reason: revoked|expired|suspended}` so the client can show the right message. |
| `POST` | `/api/v1/device/heartbeat` | `{client_version, connected: bool}` → `{ok, config_version}`; drives "last seen" and tells the client to refresh config if the policy changed. |
| `POST` | `/api/v1/device/rotate-key` | `{new_public_key}` → new config; old key removed atomically. |
| `GET` | `/api/v1/health` | liveness only; no details. |

Admin (session cookie + TOTP, CSRF, role checks, IP allowlist):

`/admin/customers`, `/admin/customers/{id}/codes`, `/admin/devices/{id}/revoke`,
`/admin/customers/{id}/suspend`, `/admin/policies`, `/admin/jobs`,
`/admin/audit`, plus a JSON mirror under `/api/v1/admin/*` for scripting.

Nothing in any request can carry a shell command, a file path, or an
arbitrary nftables fragment; the only free-text that reaches the firewall
generator is validated CIDR/port lists.

### 3.7 Provisioning pipeline (atomic, auditable, restart-safe)

1. API request runs in a single DB transaction: validate code → allocate next
   free IP in the customer's block → insert `device` → insert
   `provisioning_job(pending)` → commit. The response is **not** sent yet.
2. The provisioner applies the job: `wgctrl.ConfigureDevice` (add peer with
   /32 AllowedIPs) → regenerate and `nft -f` the firewall table → mark job
   `applied` → audit → respond to the client. Failure marks the job `failed`,
   removes the peer if it was added, and returns `503` with a job id for the
   admin "provisioning errors" view; the IP is released.
3. On every start, and every 60 s, the **reconciler** compares DB ↔ live `wg0`
   peers ↔ nftables table and converges them (adds missing, removes unknown
   peers, rebuilds the table). This also makes `wg-quick` restarts safe and
   gives rollback: restore the SQLite backup and the reconciler restores the
   hub.
4. Revocation / expiry / suspension = state change in DB → job(remove) → peer
   deleted and rules dropped within seconds; the running tunnel's handshake
   fails on the next rekey (≤ 2 min) and the client shows "Access revoked".
5. Nightly `sqlite3 .backup` + copy of `/etc/wireguard/wg0.conf` and
   `/etc/nftables.d/dishnet.nft` to `/var/backups/dishnet/`, 14-day rotation.

### 3.8 Windows client behaviour

* First run: generate keypair → activation screen → `POST /activate` → write
  DPAPI-encrypted config → install service `DishNetTunnel$office` (UAC prompt
  explained in-app: "Windows needs permission to install the DishNet secure
  tunnel driver"). Subsequent connects need no elevation: the app talks to the
  service through its own small named-pipe helper service running as SYSTEM
  (installed once by the installer) so standard users can connect.
* Connect / Disconnect = start / stop the tunnel service; status is read from
  the WireGuard named pipe (`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`)
  for handshake time and byte counters.
* Auto-reconnect: the tunnel service itself is persistent; the app shows
  "Reconnecting…" when the last handshake is older than 3 min and polls the
  API on 403 to distinguish "no internet" from "revoked/expired".
* "Start with Windows": service start type Automatic + tray app via Run key.
* Diagnostics: exports a zip with app log, service status, `ipconfig`,
  handshake/transfer stats; private key and device token are redacted at the
  source (never written to logs).

---

## 4. Proposed repository layout

```
/
├── README.md
├── docs/
│   ├── phase1-architecture.md        ← this file
│   ├── admin-runbook.md              (Phase 5)
│   ├── customer-install-guide.md     (Phase 5)
│   └── licensing-and-signing.md      (Phase 5)
├── server/                            Go module: github.com/dishnetafrica/wiregaurd/server
│   ├── cmd/dishnet-vpnd/main.go
│   ├── internal/api/                  handlers, auth, rate limit, validation
│   ├── internal/admin/                dashboard handlers + templates (red/white)
│   ├── internal/store/                SQLite, migrations, transactions
│   ├── internal/ipam/                 /29 block + address allocation
│   ├── internal/wg/                   wgctrl wrapper (interface)
│   ├── internal/firewall/             nft table generator + applier
│   ├── internal/provision/            jobs, reconciler, backup
│   ├── internal/policy/               access modes, overlap checks, Tally templates
│   └── ...                            *_test.go next to each package; integration test with a netns
├── deploy/
│   ├── install.sh                     idempotent: user, capabilities, systemd units, Caddy, nftables include
│   ├── preflight.sh                   runs the §7 inspection and backs up /etc/wireguard, iptables, nft
│   ├── rollback.sh                    restores the backup set
│   ├── systemd/dishnet-vpnd.service
│   ├── nftables/dishnet-base.nft      base table (default drop, established accept)
│   └── caddy/Caddyfile
├── windows/
│   ├── DishNetSecureConnect.sln
│   ├── src/DishNet.SecureConnect.App/     WPF UI
│   ├── src/DishNet.SecureConnect.Core/    activation, key store (DPAPI), API client, config writer
│   ├── src/DishNet.SecureConnect.Service/ SYSTEM helper service (tunnel install/start/stop, pipe)
│   ├── third_party/wireguard/             tunnel.dll, wireguard.dll + LICENSE (MIT), attribution
│   ├── installer/DishNetSecureConnect.iss Inno Setup script
│   └── tests/
└── .github/workflows/                 go test / vet; dotnet build + installer on windows-latest
```

### Changes to the live server (Phase 2, only after §7 inspection and backup)

| File | Change |
|---|---|
| `/etc/wireguard/wg0.conf` | Remove `PostUp/PostDown` FORWARD rules; keep `[Interface]` only (same key, same address, same port). No `[Peer]` blocks — peers are managed live. |
| `/etc/nftables.conf` | `include "/etc/nftables.d/*.nft"`; enable `nftables.service`. |
| `/etc/nftables.d/dishnet.nft` | Generated table `inet dishnet` — never edited by hand. |
| `/etc/systemd/system/dishnet-vpnd.service` | New, `User=dishnet`, `AmbientCapabilities=CAP_NET_ADMIN`, `ProtectSystem=strict`. |
| `/etc/caddy/Caddyfile` | New: `vpn.dishnet.africa` → `127.0.0.1:8080`. |
| DO Cloud Firewall | Allow UDP 51820 any; TCP 443 any; TCP 22 admin IPs only; deny all else. |
| `/etc/ssh/sshd_config` | **Not changed** by scripts. |

Every script is dry-run by default (`--apply` to execute), prints the diff,
backs up to `/var/backups/dishnet/<timestamp>/` and never touches SSH or the
existing `wg0` key/address/port.

---

## 5. Open questions (answer before Phase 2)

1. **DNS name** for the API/dashboard (`vpn.dishnet.africa`?) — needed for TLS.
2. **Admin IP allowlist** for SSH and `/admin` — your office/static IPs.
3. **Customer size for the pilot** — confirm `/29` (6 devices per customer) is enough; otherwise use `/28` (14 devices, 14 customers in the /24).
4. **Office server OS**: Windows PC/Server running the same client in "gateway" role (simplest) vs a Linux/MikroTik gateway (Mode B)? This decides whether the Windows client needs the "gateway" role in the MVP.
5. **Subscription model**: fixed end-date per customer set by admin (proposed) vs integration with billing later.
6. Who signs the Windows build — DishNet buys an OV/EV certificate, or ship unsigned for the pilot and accept SmartScreen warnings?

---

## 6. Phase plan and tests

| Phase | Deliverable | Tests |
|---|---|---|
| 2 | `server/` + `deploy/` | unit: ipam (no duplicates under 100 concurrent activations), code hashing/single-use, policy overlap, nft generator golden files; integration: wgctrl + nft in a Linux network namespace (CI runs as root in a container). |
| 3 | `windows/` client + installer | unit: config rendering, DPAPI key store, API client error mapping; manual: UAC flow, service install/upgrade/uninstall on Win10, Win11, Server 2022. |
| 4 | Two real Windows devices + one office server through the hub | handshake, A→server OK, A→B denied, revoked/expired denied within 2 min, reboot/restart/upgrade/uninstall. |
| 5 | Signed installer, runbook, customer guide, licensing doc | — |

---

## 7. What I need from the server (run as root, paste the output)

```bash
sudo bash -c '
echo "## wg0.conf (keys redacted)"; sed -E "s/(PrivateKey|PresharedKey) *=.*/\1 = <redacted>/" /etc/wireguard/wg0.conf
echo "## wg show"; wg show
echo "## ip"; ip -br addr; ip route
echo "## iptables"; iptables-save; echo; nft list ruleset
echo "## ufw"; ufw status verbose
echo "## sysctl"; sysctl net.ipv4.ip_forward
echo "## listening"; ss -lntup
echo "## services"; systemctl list-units --type=service --state=running --no-pager
echo "## packages"; dpkg -l | grep -Ei "wireguard|nftables|iptables|ufw|nginx|caddy|apache|docker|fail2ban" | awk "{print \$2, \$3}"
echo "## ssh"; sshd -T | grep -Ei "^(port|passwordauthentication|permitrootlogin|pubkeyauthentication) "
echo "## os"; lsb_release -d; uname -r; free -m; df -h /
'
```

Plus a screenshot or export of the **DigitalOcean Cloud Firewall** attached to
the Droplet (if any), and confirmation that `/etc/wireguard/` has been backed
up (`sudo tar czf /root/wireguard-backup-$(date +%F).tgz /etc/wireguard`).

Alternatively, give this environment SSH access (a deploy key for a
non-root user with sudo, and allow the sandbox to reach port 22) and I will run
`deploy/preflight.sh` myself in dry-run mode.

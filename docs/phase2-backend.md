# Phase 2 — VPN backend: what was built, how to stage it, blockers

Status: **implemented and tested locally (dry-run backends). Not deployed.
No change has been made to the hub at 165.227.89.92.**

---

## 1. Implementation plan → delivered

| # | Deliverable | Where | State |
|---|---|---|---|
| 1 | Go backend + migrations | `server/` (`cmd/dishnet-vpnd`, `internal/store/migrations`) | done |
| 2 | Customer/device registration + activation API | `internal/api`, `internal/provision` | done |
| 3 | WireGuard peer provisioning / revocation | `internal/wg` (netlink via `wgctrl`), `internal/provision` | done, kernel path untested until staging |
| 4 | nftables isolation rules | `internal/firewall`, `internal/policy` | done; generated file verified with `nft -c` |
| 5 | Automated tests + security review | `*_test.go` (26 tests), §5 below | done |
| 6 | Deployment, backup, rollback | `deploy/preflight.sh`, `install.sh`, `rollback.sh`, systemd, Caddy | done, dry-run by default |
| 7 | Staging procedure that doesn't touch the live VPN | §4 | documented |
| — | Admin dashboard (red/white) | `internal/admin` | done (basic) |

Run the suite: `cd server && go test -race ./...`

### Package map

```
server/cmd/dishnet-vpnd      entry point: serve | admin-create | render-firewall | reconcile-once
server/internal/store        SQLite (WAL), migrations, transactional queries
server/internal/ipam         /28 block + address allocation (pure functions)
server/internal/auth         activation codes, device tokens, argon2id passwords, sessions
server/internal/policy       port/LAN validation, DB → desired hub state (peers, rules, routes)
server/internal/firewall     nftables renderer (deterministic) + `nft -c`/`nft -f` applier
server/internal/wg           peer sync via netlink; never touches key/port/address
server/internal/provision    activation, revocation, policies, Apply/Reconcile, jobs, audit
server/internal/api          device-facing JSON API, rate limits, strict input
server/internal/admin        dashboard: sessions, CSRF, roles, IP allowlist
server/internal/ratelimit    sliding-window limiter
```

---

## 2. How provisioning works (the part that matters for safety)

1. **Activation** is one SQLite transaction: code lookup by hash → checks
   (revoked / expired / uses / customer active & unexpired / device limit /
   LAN validity) → allocate lowest free address in the customer's block →
   `UPDATE ... SET uses = uses+1 WHERE uses < max_uses` (the atomic
   single-use guard) → insert device + job → commit. Writers are serialised
   (`SetMaxOpenConns(1)` + WAL), so 40 concurrent activations of one code
   yield exactly 14 devices with 14 distinct addresses (tested).
2. **Apply** recomputes the *entire* desired hub state from the database and
   converges: firewall first (tighten), then routes, then peers. Everything
   is idempotent, so a crash at any step is repaired by the next reconcile
   (every 60 s and at start-up). Nothing is ever appended by hand to
   `wg0.conf`; peers live in the kernel + the database.
3. A device is on the hub **only if** it is `active` *and* its customer is
   `active` *and* not past `subscription_expires_at`. Revocation, suspension
   and expiry are therefore the same mechanism: the peer and its rules simply
   stop being part of the desired state. Expiry needs no job — the periodic
   reconcile drops the peer within a minute of the deadline.
4. Server-side `AllowedIPs` are the device's exact `/32` (+ declared LANs for
   gateways). Cryptokey routing drops any packet whose source does not match
   before the firewall even sees it.
5. nftables: `table inet dishnet` is replaced atomically with `nft -f` (after
   `nft -c`). Base chains have `policy accept` so other interfaces are
   untouched; traffic entering from `wg0` is sent with `goto` to a chain that
   ends in `counter drop`. Per-device rules are `ip saddr <client> ip daddr
   <gateway|LAN> tcp dport {…} accept`. Even if the old `iptables FORWARD
   ACCEPT` rule is still in the kernel, a drop in our chain wins (both base
   chains are evaluated; any drop is final).

### Address plan

Implemented as decided: `/28` per customer from `10.20.0.0/24`; block 0
reserved; first/last address of each block unused. See `address-plan.md`.
Additional pools are inserted into `address_pools` (CLI/UI for that is a
follow-up; `EnsurePool` exists).

---

## 3. API contract (v1)

Base: `https://<DISHNET_DOMAIN>`; JSON; `Content-Type: application/json`
required; unknown fields rejected; bodies ≤ 16 KB.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| `GET` | `/api/v1/health` | none | — | `{"status":"ok"}` |
| `POST` | `/api/v1/activate` | none; **5 / IP / 10 min** | `{code, public_key, device_name, os, client_version, lan_subnets?[]}` | `201 {device_token, config}` |
| `GET` | `/api/v1/device/config` | `Authorization: Bearer <device_token>` | — | `200 config` or `403 {code:"access_denied", reason: revoked\|suspended\|expired}` |
| `POST` | `/api/v1/device/heartbeat` | Bearer | `{client_version, connected}` | `200 {ok, config_version}` or `403` as above |
| `POST` | `/api/v1/device/rotate-key` | Bearer | `{new_public_key}` | `200 config` |

`config`:

```json
{
  "device_id": 12, "device_name": "Accounts laptop", "role": "client",
  "customer_name": "Kampala Traders",
  "address": "10.20.0.18/32",
  "hub_public_key": "UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs=",
  "endpoint": "165.227.89.92:51820",
  "allowed_ips": ["10.20.0.17/32"],
  "persistent_keepalive": 25,
  "dns": [],
  "access": [{"label": "Office server", "target": "10.20.0.17", "proto": "tcp", "ports": [3389, 9000]}],
  "config_version": 3,
  "subscription_expires_at": "2027-01-31T23:59:59Z"
}
```

The Windows client renders this into a tunnel configuration with its locally
generated private key. `allowed_ips` for a client is only the authorised
targets (split tunnel); for a gateway it is the customer's `/28` so replies
to clients return through the tunnel. Error codes: `invalid_code`,
`code_used`, `code_expired`, `code_revoked`, `customer_blocked`,
`device_limit`, `bad_public_key`, `duplicate_key`, `lan_not_allowed`,
`block_full`, `provisioning_failed`, `rate_limited`, `unauthorized`,
`access_denied`.

`config_version` increments whenever anything about the customer's policies
or devices changes; the client refetches when the heartbeat reports a newer
version.

---

## 4. Staging procedure (no impact on the live VPN)

**Stage 0 — laptop / CI (done).** `DISHNET_DRY_RUN=true` swaps the kernel,
nftables and route backends for in-memory fakes. The whole flow (admin →
customer → code → activation → config → revoke) runs against the real HTTP
handlers and SQLite. `go test ./...` covers it; `dishnet-vpnd
render-firewall` prints the exact nftables file a given database implies.

**Stage 1 — throw-away Droplet (recommended, ~1 hour, $0.01).**
Create a second Ubuntu 24.04 Droplet, install `wireguard nftables`, create a
`wg0` with a *new* key and the same `10.20.0.0/24` plan, then run
`deploy/install.sh --apply` there with `DISHNET_WG_ENDPOINT=<staging ip>:51820`.
Register two customers with `wg` on two Linux/Windows test machines and
verify, in this order:

1. `wg show wg0` lists the activated peers with `/32` allowed-ips.
2. `nft list table inet dishnet` shows the per-device rules, default deny.
3. Client A → gateway A: `ping` fails (ICMP not in policy, expected), RDP/TCP
   on the allowed port connects.
4. Client A → gateway B: blocked (counter on "dishnet default deny" rises).
5. Revoke client A in the dashboard: `wg show` loses the peer within 1 s; the
   client's next handshake fails; `/device/config` returns 403 `revoked`.
6. `systemctl restart wg-quick@wg0` (peers vanish) → within 60 s
   `dishnet-vpnd` re-adds them; `systemctl restart dishnet-vpnd` → same.
7. Reboot the Droplet: all of the above holds without intervention.
8. `deploy/rollback.sh <backup>` returns the box to its pre-install state.

**Stage 2 — production hub.** Only after Stage 1 passes and DishNet has
supplied the items in §6: `preflight.sh` → review the printed audit →
`install.sh` (dry run) → review → `install.sh --apply` → the same 8 checks
with one pilot customer. The live `wg0` keeps its key, address and port
throughout; the only interruption is none (nftables and peers are applied
live) unless you choose to flush the stale iptables rule (≈2 s).

### What `install.sh --apply` changes on the hub

| Path | Change | Reversible by |
|---|---|---|
| `/var/backups/dishnet/<stamp>/` | backup set written first | — |
| packages | `nftables sqlite3 caddy` installed | `rollback.sh` leaves packages |
| user `dishnet`, `/var/lib/dishnet`, `/etc/nftables.d`, `/etc/dishnet` | created | manual |
| `/usr/local/bin/dishnet-vpnd` | installed | manual |
| `/etc/nftables.conf` | one `include` line appended | `rollback.sh` |
| `/etc/nftables.d/dishnet.nft` | generated table | `rollback.sh` (deletes table) |
| `/etc/wireguard/wg0.conf` | `PostUp/PostDown` lines removed (key/address/port untouched) | `rollback.sh` |
| ufw (if active) | `route allow in on wg0 out on wg0`, allow 51820/udp, 443/tcp | manual `ufw delete` |
| `/etc/systemd/system/dishnet-vpnd.service`, `/etc/dishnet/dishnet-vpnd.env` | created | `rollback.sh` stops/disables |
| `/etc/caddy/Caddyfile` | written for `$DISHNET_DOMAIN` | `rollback.sh` |
| sshd, DO cloud firewall, server private key, subnet, port | **never touched** | — |

---

## 5. Security review of the backend

Reviewed against the Phase 1 requirements. ✔ = implemented and covered by a
test; ◐ = implemented, needs the staging run; ✗ = not yet.

| Requirement | State | Notes |
|---|---|---|
| Tenant isolation (no cross-customer forwarding) | ✔ | `TestCustomersCannotReachEachOther` incl. a hand-inserted cross-tenant policy row being ignored |
| Default-deny forwarding | ✔ | golden file + `nft -c` |
| No peer-to-peer except policy; gateway cannot initiate to clients | ✔ | rules are client→gateway only |
| No internet routing via hub | ✔ | no NAT rule; `0.0.0.0/0` never issued; `vpn_to_hub` drops all but ping |
| Unique keys and addresses | ✔ | UNIQUE constraints + 40-way concurrency test |
| Single-use / limited codes, expiry, revocation | ✔ | |
| Rate-limited activation | ✔ | 5/IP/10 min (HTTP test); codes carry 80 bits of entropy |
| Device revocation, subscription expiry, suspension | ✔ | peers removed, config 403 with reason |
| Private key never leaves device | ✔ | API has no field for it; unknown JSON fields rejected |
| Server private key not exposed | ✔ | service user cannot read `/etc/wireguard`; hub key read from the interface via netlink |
| Secrets not in logs/responses | ✔ | `TestNoSecretsInConfigOrAudit`; codes stored as SHA-256, tokens as SHA-256, passwords argon2id |
| HTTPS for API + admin | ◐ | Caddy config provided; needs the DNS name |
| No arbitrary shell | ✔ | only `/usr/sbin/nft -f <fixed path>` and `/usr/sbin/ip route replace <validated cidr> dev wg0` |
| Atomic, auditable, restart-safe provisioning | ✔ | `TestRestartRecoveryRepopulatesEmptyHub`, `TestProvisioningFailureIsRecordedAndRecovered` |
| Backup / rollback | ◐ | scripts written; exercised in staging |
| Admin auth + RBAC | ✔ | owner/operator/viewer, CSRF, SameSite=Strict, IP allowlist, login rate limit |
| Admin MFA (TOTP) | ✗ | follow-up before broad launch; IP allowlist mitigates |
| SMB blocked by default | ✔ | explicit audited override only |
| LAN overlap prevention (Mode B) | ✔ | across customers and against pools; RFC 1918 only |

Known limitations / follow-ups:

* Stale `ip route` entries for a removed Mode B LAN remain until reboot
  (harmless: no peer carries that allowed-IP and the firewall denies it).
* Rate limits are in-memory, per process.
* Revoked addresses are never recycled; with 14 per block a customer that
  churns many devices will need a bigger block (admin can create a new
  customer record) — acceptable for the pilot, flagged for the address plan.
* Admin TOTP, pool management UI and audit-log export are not built.

---

## 6. Blockers before any live-infrastructure change

1. **Server audit output** (`phase1-architecture.md` §7) — or run
   `deploy/preflight.sh` and send me `/tmp/dishnet-preflight-*.txt`. In
   particular: is ufw active, is iptables-nft or legacy in use, are there
   static `[Peer]` blocks, what else listens on 80/443.
2. **DNS**: an A record `vpn.dishnetuganda.com → 165.227.89.92` and
   confirmation that port 80/443 are open in the DO cloud firewall (needed
   for Let's Encrypt).
3. **Admin IP allowlist** value for `DISHNET_ADMIN_ALLOW`.
4. **Backup confirmation** (`/root/wireguard-backup-<date>.tgz`, mode 600).
5. **A staging Droplet or permission to use the live hub directly** — I
   recommend staging; see §4.
6. **Access for me**: either SSH into the hub/staging box from this
   environment, or you run the scripts and paste the output.

Nothing in this phase builds the Windows client; that starts (Phase 3) once
Stage 1 above has passed.

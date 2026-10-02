# DishNet Secure Connect

Managed remote-access VPN service for DishNet customers in Uganda: a
DishNet-branded Windows client, a management backend and an administrator
dashboard on top of the existing WireGuard hub at 165.227.89.92.
Powered by WireGuard®.

| Component | Path | Status |
|---|---|---|
| Management service (`dishnet-vpnd`): device API, admin dashboard, WireGuard + nftables provisioner | `server/` | **Live** at https://vpn.dishnetuganda.com (v0.1.0) |
| Hub deployment: preflight audit, installer (dry-run by default), rollback, systemd, Caddy | `deploy/` | **Deployed to 165.227.89.92 on 2026-10-02** (v0.1.0) |
| Windows client + installer | `windows/` | Phase 3 — app, Windows integration and installer built; CI produces `DishNetSecureConnect-Setup-<ver>.exe`; awaiting Phase 4 on real hardware |

## Documents

* [`docs/phase1-architecture.md`](docs/phase1-architecture.md) — findings, architecture, risks
* [`docs/decisions.md`](docs/decisions.md) — approved decisions
* [`docs/address-plan.md`](docs/address-plan.md) — `/28` plan, capacity, growth beyond the `/24`
* [`docs/phase2-backend.md`](docs/phase2-backend.md) — what was built, API contract, staging procedure, security review
* [`docs/server-audit-2026-10-02.md`](docs/server-audit-2026-10-02.md) — hub audit findings
* [`docs/deployment-runbook.md`](docs/deployment-runbook.md) — exact commands, expected output, rollback, SSH safety, test results

## Quick start (development, nothing touched on this machine)

```bash
cd server
go test ./...
go build -o dishnet-vpnd ./cmd/dishnet-vpnd

export DISHNET_DRY_RUN=true DISHNET_DB=/tmp/dishnet.db DISHNET_LISTEN=127.0.0.1:8080 \
       DISHNET_INSECURE_COOKIES=true DISHNET_TRUST_PROXY=false
DISHNET_ADMIN_PASSWORD='choose-a-long-password' ./dishnet-vpnd admin-create you@example.com owner
./dishnet-vpnd serve            # http://127.0.0.1:8080/admin
./dishnet-vpnd render-firewall  # print the nftables rules the database implies
```

## Hub deployment (after review — see docs/phase2-backend.md §4)

```bash
sudo bash deploy/preflight.sh                       # read-only audit + backup
sudo DISHNET_DOMAIN=vpn.dishnetuganda.com DISHNET_ADMIN_ALLOW=203.0.113.5 bash deploy/install.sh           # dry run
sudo DISHNET_DOMAIN=vpn.dishnetuganda.com DISHNET_ADMIN_ALLOW=203.0.113.5 bash deploy/install.sh --apply
sudo bash deploy/rollback.sh /var/backups/dishnet/<stamp>   # if anything is wrong
```
* [`docs/pilot-test.md`](docs/pilot-test.md) — first two-device test with the official WireGuard client and `tools/activate.*`
* [`docs/phase3-windows.md`](docs/phase3-windows.md) — Windows client design and progress

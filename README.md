# DishNet Secure Connect

Managed remote-access VPN service for DishNet customers in Uganda: a
DishNet-branded Windows client, a management backend and an administrator
dashboard on top of the existing WireGuard hub at 165.227.89.92.
Powered by WireGuard®.

| Component | Path | Status |
|---|---|---|
| Management service (`dishnet-vpnd`): device API, admin dashboard, WireGuard + nftables provisioner | `server/` | Phase 2 — implemented, tested with dry-run backends, **not deployed** |
| Hub deployment: preflight audit, installer (dry-run by default), rollback, systemd, Caddy | `deploy/` | Phase 2 — written, awaiting staging |
| Windows client + installer | `windows/` | Phase 3 — not started |

## Documents

* [`docs/phase1-architecture.md`](docs/phase1-architecture.md) — findings, architecture, risks
* [`docs/decisions.md`](docs/decisions.md) — approved decisions
* [`docs/address-plan.md`](docs/address-plan.md) — `/28` plan, capacity, growth beyond the `/24`
* [`docs/phase2-backend.md`](docs/phase2-backend.md) — what was built, API contract, staging procedure, security review, blockers

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

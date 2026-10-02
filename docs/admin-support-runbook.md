# DishNet Secure Connect — Admin & support runbook

Version 1.0 · 2026-10-02 · For DishNet administrators and technical support

Companion to `customer-onboarding-sop.md` (who does what) and
`deployment-runbook.md` (hub installation). This document is for the
day-to-day: diagnosing a customer problem, operating the hub, and escalating.

## 1. Where to look first

| Question | Where |
|---|---|
| Is this customer active, on trial, expired? | Dashboard → Customers → customer page (plan card) |
| Is the office computer online? | Customer page → Devices: gateway row **online** = handshake < 3 min |
| Why can't staff connect? | Customer page → **Support view** (`/support`): per-symptom table |
| What did we agree with them? | Customer page → Support notes |
| Did provisioning fail on the hub? | Overview → *Failed provisioning jobs* → Provisioning |
| Who did what, when? | Audit log |

Information in the dashboard is labelled **verified** (observed by the
system: registrations, handshakes, approvals) or **entered** (typed by an
administrator or reported by the customer). Never promote an *entered* fact
to a *verified* one in conversation with a customer.

## 2. Symptom → cause → action

| Symptom (customer's words) | Observe | Cause | Action |
|---|---|---|---|
| "It says Connecting… forever" | Device handshake never/old | Laptop has no internet; or device revoked/expired | Ask them to open a website; check plan status; re-issue code if revoked |
| "Reconnecting…" | Handshake went stale | Their internet dropped | Nothing — reconnects by itself |
| "Office computer not answering" | Gateway offline / never connected | Office PC off, asleep, offline; Allow not clicked; Windows Home | Office opens the app, checks Connected and Allow; confirm edition in onboarding |
| "Remote Desktop won't connect" (but office online) | Policy present? Allow clicked? | No policy, or RDP not enabled on the office PC | Add policy (3389); CIT clicks Allow in the office app |
| "Sign-in failed" | — | Wrong Windows user/password or account without password | CIT resets the Windows password; DishNet never handles it |
| "Access revoked" / "trial ended" | Plan / device status | Expired, suspended or revoked | Extend / mark paid / reactivate; new code if revoked |
| "Update now does nothing" | Hub `/api/v1/client/latest` | Installer cache missing on hub | `sudo bash deploy/fetch-installer.sh` on the hub |
| Everyone offline at once | `systemctl status dishnet-vpnd caddy wg-quick@wg0` on hub | Hub problem | §4 |

The staff app's **Something is not working…** assistant classifies a failure
into one of six layers; ask the customer what it said, and use the same
language:

| Layer | Observe in the dashboard | Owner |
|---|---|---|
| 1 Activation | Device missing / revoked; plan expired | DishNet (AD) |
| 2 DishNet connection | Device handshake never/old | Customer (their internet) |
| 3 Office computer | Gateway offline; edition Home; Allow not clicked (gateway firewall note) | Customer IT contact |
| 4 Remote Desktop | Gateway online + policy present, yet RDP refused → Allow not clicked | Customer IT contact |
| 5 Windows sign-in | Not observable | Customer IT contact (never DishNet) |
| 6 Tally | Not observable | Customer's Tally provider |

Always add a support note after each contact: what was observed, what was agreed, next step and owner.

## 3. Routine admin tasks

| Task | Where / command |
|---|---|
| Create customer / codes | Dashboard → Customers |
| Approve trial request | Dashboard → Trial requests → Approve (links shown once) |
| Extend trial / mark paid / suspend | Customer page → plan card |
| Revoke a device (staff left) | Customer page → Devices → Revoke (cut off within a minute) |
| Record onboarding facts, readiness, acceptance, handover | Customer page → Onboarding form |
| Record the Tally company, simultaneous-users need and assessment, the 8-point pilot checklist | Customer page → Onboarding form (acceptance is refused until all 8 are ticked) |
| Add administrator | Administrators (owner role only) |
| Publish a new Windows client | GitHub → Actions → windows-client → Run workflow → version; then on hub `sudo bash deploy/fetch-installer.sh` |
| Update the hub service | GitHub → Actions → server → Run workflow → version; then on hub `sudo bash deploy/update-server.sh` |
| Rebuild the customer manual | `python3 tools/build-manual.py` (commit the outputs), then release the server |
| Change the support contact | `/etc/dishnet/dishnet-vpnd.env` → `DISHNET_SUPPORT_CONTACT` → `systemctl restart dishnet-vpnd`; and `docs/manual/config.json` for the manual |

## 4. Hub health (SSH, root)

```bash
systemctl status dishnet-vpnd caddy wg-quick@wg0 --no-pager | grep -E "Active|●"
journalctl -u dishnet-vpnd -n 30 --no-pager            # look for "hub converged" every minute
wg show wg0 | grep -E "peer|handshake"                 # live peers
nft list chain inet dishnet vpn_from_peer              # default-deny chain with per-device accepts
curl -s http://127.0.0.1:8080/api/v1/health            # {"status":"ok"}
df -h / ; free -m                                      # disk, memory (swap 1 GB)
```

Recovery:

| Problem | Action |
|---|---|
| `dishnet-vpnd` not active | `systemctl restart dishnet-vpnd`; read `journalctl -u dishnet-vpnd -n 50` |
| Caddy certificate errors | `journalctl -u caddy -n 50`; check DNS `vpn.dishnetuganda.com` → 165.227.89.92 and TCP 80/443 open in the DO firewall |
| Peers missing after a reboot | wait one minute (reconciler), or Dashboard → Provisioning → *Reconcile hub now* |
| Need to roll back a server update | `bash deploy/update-server.sh vX.Y.Z` with the previous version |
| Need to roll back the whole installation | `bash deploy/rollback.sh /var/backups/dishnet/<stamp>` (see deployment-runbook §6) |

Never edit `/etc/wireguard/wg0.conf` peers or `/etc/nftables.d/dishnet.nft`
by hand — the service owns them and will overwrite them.

## 5. Escalation

| Level | Who | When |
|---|---|---|
| L1 | Support (TS) | All customer contacts; §2 table |
| L2 | Administrator (AD) | Plan/billing changes, device limits, suspensions, hub restarts |
| L3 | Engineering (repository maintainers) | Hub down and not recovered by restart; provisioning jobs failing repeatedly; app error reproducible on a clean PC; any suspected security issue |

For L3 collect: customer id, device ids, the app's diagnostics zip (contains
no secrets), `journalctl -u dishnet-vpnd -n 200`, and the exact time.
Open an issue in the repository or contact the maintainer; include nothing
that looks like a key, code or password.

## 6. Security rules for staff

- Treat install links and activation codes as secrets: send only to the customer's named contacts.
- Never ask for Windows or Tally passwords; if a customer sends one, tell them to change it.
- Dashboard accounts: one per person, owner role only for those who manage administrators. Sign out on shared computers.
- Set the dashboard IP allowlist (`DISHNET_ADMIN_ALLOW`) once DishNet's admin IPs are known; until then the dashboard relies on passwords and rate limiting.
- The hub's SSH: key-only, root password login disabled, port 22 restricted in the DigitalOcean firewall (deployment-runbook §2.1).

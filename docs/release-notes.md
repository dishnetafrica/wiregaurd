# DishNet Secure Connect — release notes and rollback

Each release lists what changed, how it was verified, the exact hub commands,
and how to roll back. Server releases are tags `vX.Y.Z` (Linux binary
`dishnet-vpnd-linux-amd64` + `.sha256`); client releases are tags
`client-vX.Y.Z` (`DishNetSecureConnect-Setup-X.Y.Z.exe`; the hub computes and
publishes its SHA-256 in `/api/v1/client/latest` when it fetches it). Both are
published from GitHub Actions (*Run workflow* → version); the hub never
builds anything itself.

## Server v0.6.1 / client 0.4.1 — 2026-10-02 (no duplicate office computers)

Found in the pilot: the office PC KISHAN had registered five times (devices
10.20.0.65–.69), each reinstall from the install link creating a new device
and another default policy, and using up the 5-use gateway code.

- **Client 0.4.1 (installer only):** uninstalling no longer deletes the
  device identity and settings; only logs and the rendered tunnel file go.
  A reinstall or an upgrade from an install link therefore resumes the
  existing registration instead of creating a new one. Retiring a device is
  done with *Reset this device* in the app or by revocation in the dashboard.
- **Server v0.6.1:** when an office computer activates again under the same
  name (case-insensitive) for the same customer, the hub treats it as a
  replacement: the old gateway record is revoked, its peer removed, its
  policies deleted, and the event is audited as `device.replaced`. Staff
  laptops are never replaced implicitly. Revoking any device now also deletes
  the policies that named it, so dead rules never linger.
- No schema change. Existing duplicates (KISHAN .67 and .68) are cleaned up
  by revoking them in the dashboard once; .69 stays as the live office PC.

Verified assets: `v0.6.1/dishnet-vpnd-linux-amd64` reports `dishnet-vpnd
7dd15c2`, sha256 matches; `client-v0.4.1/DishNetSecureConnect-Setup-0.4.1.exe`
55,822,768 bytes, sha256
`118d791133ba1afd922c33531a2fc28793c57648add9a679feccee22f96bc350`.

Deploy: `sudo bash deploy/update-server.sh v0.6.1` and
`sudo bash deploy/fetch-installer.sh client-v0.4.1`. Rollback: `v0.6.0` /
`client-v0.4.0`.

## Server v0.6.0 / client 0.4.0 — 2026-10-02 (remote Tally as the main journey)

The product now teaches one thing: doing Tally accounting from another
location, with DishNet Secure Connect behind the scenes.

**Windows client 0.4.0**
- **Set up Tally remote access**: a guided, eight-step journey on the staff
  laptop (activate → connect → office reachable → open Remote Desktop → sign
  in → open the recorded Tally company → one simple task → finish properly).
  Software-verified steps show as checked; the customer confirms the rest,
  only in order and only when the prerequisites are verified. Includes a
  **practice run** with *Practise again*.
- **Troubleshooting assistant** (*Something is not working…*): decides from
  what the app can observe which of six layers fails (activation, DishNet
  connection, office computer, Remote Desktop, Windows sign-in, Tally) and
  asks at most three questions for the rest. Each result names who fixes it.
  A handshake never implies Tally works.
- Help centre and manual rewritten Tally-first; simultaneous-users limitation
  explained (Windows Server / RDS assessment needed).
- Consent gate, Windows Home handling, activation, key protection and in-place
  update unchanged. 0.3.x apps update in place.

**Server v0.6.0**
- Dashboard: **Remote Tally pilot checklist** (8 checks); acceptance can be
  recorded only when all 8 are ticked. Tally company name (sent to staff apps
  in their config), staff needing Tally simultaneously, and the Windows
  Server / RDS assessment status, with an attention item until assessed.
- Migration `0005_tally`: four additive columns on `customer_onboarding`.
  No existing rows or tables are altered.
- `/api/v1/device/config` gains `tally_company` for client devices.

Verified before release: `go vet`, `go test -race ./...` (7 packages, 39
tests), `dotnet test` (65 tests), solution build, manual rebuilt (HTML +
PDF), dashboard screenshot captured from a seeded dry-run server. Release
assets verified: `v0.6.0/dishnet-vpnd-linux-amd64` reports `dishnet-vpnd
998ce23`, sha256 matches; `client-v0.4.0/DishNetSecureConnect-Setup-0.4.0.exe`
55,819,608 bytes, sha256
`c675ac1add49e8930c00f912334d253413908670aa70873f827b42b140758bb4`.

### Deploy (hub, as root)

```bash
cd /root/wiregaurd && git pull
sudo bash deploy/update-server.sh v0.6.0
sudo bash deploy/fetch-installer.sh client-v0.4.0
curl -s https://vpn.dishnetuganda.com/api/v1/client/latest   # expect "version":"0.4.0", sha256 c675ac1a…58bb4, size 55819608
```

### Rollback

`sudo bash deploy/update-server.sh v0.5.1` (the 0005 columns stay, unused
by v0.5.1) and `sudo bash deploy/fetch-installer.sh client-v0.3.1`.

## Server v0.5.1 / client 0.3.1 — 2026-10-02 (guided onboarding)

**Server**
- Dashboard onboarding progress per customer: every item labelled *verified*
  (handshakes, registrations, approvals, the office app's own report) or
  *entered* (typed by an admin). Next action + owner on the customers list,
  the customer page and the new **Support view**.
- Office Windows edition is now **verified from the office app** (it reports
  e.g. `Windows 11 Pro …`); an admin's entry is used only when no office
  device has reported yet. Home → attention with the Pro/other-PC advice.
- Support notes per customer; notes containing a password are refused.
- Public customer manual at `/guide` and `/guide.pdf`, support contact
  from `DISHNET_SUPPORT_CONTACT` (default WhatsApp 0705 993 348) is sent to
  the apps with every config.
- Migration `0004_onboarding` adds `customer_onboarding` and `support_notes`
  (additive only; no existing table is altered or dropped).

**Windows client 0.3.1**
- First-launch tour, guided checklist (Pending / Verified / Confirmed /
  Attention), help centre, *Contact support* (WhatsApp), diagnostics zip.
- **Consent gate:** the office app never enables Remote Desktop or touches
  the firewall until the owner/operator clicks *Allow* after reading what
  changes. Firewall rule is limited to TCP 3389 from the customer's VPN block.
- **Windows Home detection:** on a Home edition the *Allow* button is
  disabled and the app explains that Home cannot accept Remote Desktop and
  recommends Windows Pro or another office PC.
- Office reachability probe (TCP 3389 over the tunnel) drives the
  "Office computer reachable" step; the handshake alone never does.
- Activation, DPAPI-protected private key and in-place update (*Update now*)
  unchanged from 0.2.x; 0.2.x apps update to 0.3.1 without uninstalling.

**Verified before release** (see the completion report for the run ids):
`go vet` + `go test -race ./...` (7 packages), `dotnet test` (61 tests),
Windows solution build, release workflows green, binary and installer
binary checksum matches its `.sha256` asset.

| Asset | Size | SHA-256 |
|---|---|---|
| `v0.5.1/dishnet-vpnd-linux-amd64` (reports `dishnet-vpnd a6e943d`) | 13,807,800 | see `.sha256` asset (verified OK) |
| `client-v0.3.1/DishNetSecureConnect-Setup-0.3.1.exe` | 55,803,150 | `376bdc9cf178d665f9fedb137db794cffdd50b67d0d9db348448b19d95a51aff` |

### Deploy (hub, as root)

```bash
cd /root/wiregaurd && git pull
sudo bash deploy/update-server.sh v0.5.1          # expect: downloaded v0.5.1: dishnet-vpnd <commit> … healthy
sudo bash deploy/fetch-installer.sh client-v0.3.1 # expect: sha256 OK, cached at /var/lib/dishnet/installer/
curl -s https://vpn.dishnetuganda.com/api/v1/client/latest   # expect "version":"0.3.1" and sha256 376bdc9c…a51aff
curl -sI https://vpn.dishnetuganda.com/guide | head -1       # expect HTTP/2 200
```

Existing customers are not touched: no device, policy or customer row is
modified by this update; peers and nftables rules are reconciled from the
same records as before.

### Rollback

| What went wrong | Command (hub, root) | Effect |
|---|---|---|
| Server misbehaves after update | `sudo bash deploy/update-server.sh v0.4.0` | Reinstalls the previous binary; the `0004` tables stay (harmless, unused by v0.4.0) |
| Whole installation broken | `sudo bash deploy/rollback.sh /var/backups/dishnet/<stamp>` | Restores binary, env, DB and nft snapshot taken by `install.sh` (deployment-runbook §6) |
| Client 0.3.1 must be withdrawn | `sudo bash deploy/fetch-installer.sh client-v0.2.3` | `/api/v1/client/latest` then offers 0.2.3; 0.3.1 apps keep working, new installs get 0.2.3. A PC already on 0.3.1 can run the 0.2.3 installer over it (activation is kept). |

Never downgrade the server below v0.4.0 after this release without restoring
the matching database backup: v0.3.x and earlier do not know the `plan`
tables.

## Earlier

| Release | Date | Summary |
|---|---|---|
| v0.5.0 / client 0.3.0 | 2026-10-02 | First guided-onboarding build (superseded by 0.5.1/0.3.1 the same day: Windows-edition detection added) |
| v0.4.0 / client 0.2.3 | 2026-10-02 | In-app update, trial request page, install links with embedded codes, consent-less gateway setup fixes (error 740, ACL failure) |
| v0.3.0 / client 0.2.0 | 2026-10-01 | Plans/trial expiry, auto-activation from install link |
| v0.2.0 | 2026-10-01 | First hub deployment of dishnet-vpnd (migrations 0001–0002) |

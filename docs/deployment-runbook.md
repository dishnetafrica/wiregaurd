# Live deployment runbook — DishNet hub 165.227.89.92

**Status: prepared, NOT executed. Nothing runs on the hub until DishNet
explicitly approves step 5 and types the `--apply` command.**

Prepared against the 2026-10-02 audit (`server-audit-2026-10-02.md`) and
the installer dry run replayed against a replica of that hub's `wg0.conf`.
Expected outputs below are from that replay and from the audit, not guesses;
where the live box may differ, the line says so.

---

## 0. Design confirmation: typed operations only

The management API never exposes shell execution, raw WireGuard
configuration, or raw firewall rules. Every change passes through one of
these functions in `server/internal/provision/provision.go`, each of which
validates its input and writes an audit row:

| Operation | Function | Input that reaches the hub |
|---|---|---|
| CreateCustomer | `CreateCustomer` | allocates a `/28` block (pure arithmetic) |
| CreateCode / RevokeCode | `CreateCode`, `RevokeCode` | nothing (database only) |
| CreateDevice + AllocateVPNIP + RegisterPublicKey | `Activate` | a `wgtypes.Key` (parsed, 32 bytes) and a `netip.Addr` |
| ApplyPolicy | `CreatePolicy`, `SetPolicyEnabled`, `DeletePolicy` | validated ports (`1–65535`, SMB refused) and `netip.Prefix` |
| RevokeDevice / Suspend / Expire | `RevokeDevice`, `SetCustomerStatus`, reconciler | nothing new; peer and rules disappear from desired state |

The hub is then converged by `Apply`, which (a) renders the nftables file
from typed values only, (b) runs `/usr/sbin/nft -c -f` then `-f` on a fixed
path, (c) runs `/usr/sbin/ip route replace <netip.Prefix> dev wg0` for
declared office LANs, (d) sets peers via the WireGuard netlink socket
(`wgctrl`). No string from any request is ever passed to a shell. Tests
`TestRenderRejectsBadInput` (interface name injection, comment injection)
and `TestActivateRejectsBadInput` cover the boundary.

The WireGuard server private key is not in GitHub, not read by the service
(`/etc/wireguard` is root-only; service runs as `dishnet`), and not in any
backup that the repository tracks (`*.tgz` is git-ignored).

---

## 1. Requirements

| | Required | Hub (audit) |
|---|---|---|
| RAM for `dishnet-vpnd` | ~7 MB RSS idle (measured), < 40 MB under load | 458 MB total, 296 MB available ✔ |
| RAM for Caddy | ~25 MB | ✔ |
| RAM to **build** Go | ~1.5 GB | ✘ — use the CI binary (19 MB static, no dependencies) |
| Disk | 60 MB | 6.8 GB free ✔ |
| Ports free | 80, 443 | ✔ (only 22 and 51820 in use) |
| DNS | `vpn.dishnetuganda.com A 165.227.89.92` | ✔ (GoDaddy) |
| Swap | recommended 1 GB (OOM protection on a 512 MB Droplet) | ✘ — step 2.3 |

---

## 2. Pre-deployment (safe; no VPN impact)

### 2.1 SSH safety procedure — do this first, in this order

The audit shows `PermitRootLogin yes` and `PasswordAuthentication yes`.
Nothing in `deploy/` touches sshd. Harden it by hand, keeping one working
session open throughout:

```bash
# Terminal A (keep open the whole time)
ssh root@165.227.89.92

# 1. Make sure key login works from your Mac in a SECOND terminal before changing anything:
#    Terminal B:
ssh -o PasswordAuthentication=no root@165.227.89.92 'echo KEY-LOGIN-OK'
# expected: KEY-LOGIN-OK      (if it prompts for a password, STOP: add your key to /root/.ssh/authorized_keys first)

# 2. In the DigitalOcean control panel: Networking → Firewalls → the hub's firewall
#    (create one if none is attached) → Inbound rules exactly:
#       SSH   TCP 22     Sources: <your admin IP(s)>
#       Custom UDP 51820 Sources: All IPv4, All IPv6
#       HTTP  TCP 80     Sources: All IPv4, All IPv6     (Let's Encrypt HTTP-01 + redirect)
#       HTTPS TCP 443    Sources: All IPv4, All IPv6
#    Outbound: leave "All".  Apply, then from Terminal B:
ssh root@165.227.89.92 'echo STILL-OK'
# expected: STILL-OK

# 3. Only now disable password/root-password logins (Terminal A):
printf 'PasswordAuthentication no\nPermitRootLogin prohibit-password\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/99-dishnet.conf
sshd -t && systemctl reload ssh
sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin) '
# expected:
#   passwordauthentication no
#   permitrootlogin prohibit-password

# 4. Terminal B again:
ssh root@165.227.89.92 'echo HARDENED-OK'
# expected: HARDENED-OK.  If it fails, in Terminal A: rm /etc/ssh/sshd_config.d/99-dishnet.conf && systemctl reload ssh
```

### 2.2 Backup (already done 2026-10-02; repeat on deployment day)

```bash
tar czf /root/wireguard-backup-$(date +%F).tgz /etc/wireguard && chmod 600 /root/wireguard-backup-$(date +%F).tgz
ls -l /root/wireguard-backup-*.tgz
# expected: -rw------- 1 root root ~419 ... /root/wireguard-backup-2026-10-02.tgz
```

### 2.3 Swap (recommended)

```bash
fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab
free -m | grep Swap
# expected: Swap:          1023           0        1023
```

### 2.4 Get the binary and the repository onto the hub

Every release tag publishes a static Linux binary (built and tested by CI)
at <https://github.com/dishnetafrica/wiregaurd/releases>. On the hub:

```bash
curl -fL https://github.com/dishnetafrica/wiregaurd/releases/latest/download/dishnet-vpnd-linux-amd64 -o /root/dishnet-vpnd
curl -fL https://github.com/dishnetafrica/wiregaurd/releases/latest/download/dishnet-vpnd-linux-amd64.sha256 | sed 's| .*| /root/dishnet-vpnd|' | sha256sum -c
chmod +x /root/dishnet-vpnd && /root/dishnet-vpnd version
# expected: /root/dishnet-vpnd: OK
#           dishnet-vpnd <7-char git sha>
apt-get install -y git >/dev/null; git clone https://github.com/dishnetafrica/wiregaurd.git /root/wiregaurd 2>/dev/null || git -C /root/wiregaurd pull
cd /root/wiregaurd && git log --oneline -1
# expected: <sha> <latest commit message>
```

To publish a new version later: GitHub → Actions → **server** → *Run
workflow* → enter `vX.Y.Z`; the run tests, builds and creates the release.

---

## 3. Audit + backup set (read-only)

```bash
cd /root/wiregaurd && bash deploy/preflight.sh | tee /root/preflight-$(date +%F).txt
```

Expected `## Checks` section on the current hub:

```
WARN: unrestricted wg0 -> wg0 forwarding rule present (R1). install.sh --apply removes it from wg0.conf.
OK:   no masquerade rule
OK:   ip_forward=1
OK:   UDP 51820 listening
OK:   no static peers in wg0.conf
## Backup
wrote /var/backups/dishnet/<stamp>/wireguard.tgz
backup set: /var/backups/dishnet/<stamp> (contains private keys — keep it private)
# preflight complete — no configuration was changed
```

(No ufw warning: ufw is inactive on this hub.)

---

## 4. Dry run (read-only)

```bash
cd /root/wiregaurd
export DISHNET_BIN=/root/dishnet-vpnd DISHNET_DOMAIN=vpn.dishnetuganda.com DISHNET_ALLOW_ANY_ADMIN_IP=yes   # test phase: dashboard open to any IP (password + rate limit); set DISHNET_ADMIN_ALLOW=<ip> later
bash deploy/install.sh
```

Expected output (replayed against a replica of this hub's `wg0.conf`):

```
# DishNet hub install — vpnforstarlink — <stamp> — mode: DRY-RUN
## 1. Backup
  [plan] bash deploy/preflight.sh  (creates /var/backups/dishnet/<stamp>/)
## 2. Packages (nftables, caddy, sqlite3)
  [plan] apt-get install -y sqlite3 caddy          ← nftables already installed on this hub
## 3. Service user and directories
  [plan] useradd --system --home /var/lib/dishnet --shell /usr/sbin/nologin dishnet
  [plan] install -d -o dishnet -g dishnet -m 0750 /var/lib/dishnet
  [plan] install -d -o root -g dishnet -m 0775 /etc/nftables.d
  [plan] install -d -m 0755 /etc/dishnet
## 4. Binary
  [plan] install -m 0755 /root/dishnet-vpnd /usr/local/bin/dishnet-vpnd.new
  [plan] bash -c mv -f /usr/local/bin/dishnet-vpnd.new /usr/local/bin/dishnet-vpnd
## 5. nftables (persistent include of the generated dishnet table)
  [plan] bash -c printf '\ninclude "/etc/nftables.d/*.nft"\n' >> /etc/nftables.conf
  [plan] install -o root -g dishnet -m 0664 .../deploy/nftables/dishnet-empty.nft /etc/nftables.d/dishnet.nft
  [plan] systemctl enable nftables.service
## 6. wg0.conf — strip PostUp/PostDown forwarding rules (R1/R4)
  lines that will be removed:
    5:PostUp = iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT
    6:PostDown = iptables -D FORWARD -i wg0 -o wg0 -j ACCEPT
## 7. dishnet-vpnd service
  [plan] bash -c cat > /etc/dishnet/dishnet-vpnd.env <<EOF ... EOF
  [plan] install -m 0644 .../deploy/systemd/dishnet-vpnd.service /etc/systemd/system/dishnet-vpnd.service
  [plan] systemctl daemon-reload
  [plan] systemctl enable dishnet-vpnd
## 8. Caddy (TLS for vpn.dishnetuganda.com -> 127.0.0.1:8080)
  [plan] write /etc/caddy/Caddyfile for vpn.dishnetuganda.com and restart caddy
## 9. Start and validate
  [plan] systemctl restart dishnet-vpnd && curl http://127.0.0.1:8080/api/v1/health

Dry run complete. Nothing was changed. Re-run with --apply to perform the steps above.
```

If the live output differs from this (e.g. an unexpected `ufw` line, extra
`PostUp` lines, "static [Peer] blocks found"), stop and send it to me.

### Exact files changed by `--apply`

| File | Change | Why |
|---|---|---|
| `/etc/wireguard/wg0.conf` | delete lines 5–6 (`PostUp`/`PostDown`). `Address`, `ListenPort`, `PrivateKey` untouched; file mode untouched | R1 broad forwarding |
| `/etc/nftables.conf` | append `include "/etc/nftables.d/*.nft"` (Ubuntu's stock file keeps its `flush ruleset` + empty `table inet filter` above it, which is harmless and only runs at boot) | persistence across reboot |
| `/etc/nftables.d/dishnet.nft` | new; placeholder now, regenerated by the service | the isolation policy |
| `/etc/dishnet/dishnet-vpnd.env` | new, `root:dishnet 0640` | configuration |
| `/etc/systemd/system/dishnet-vpnd.service` | new | service, `CAP_NET_ADMIN` only |
| `/etc/caddy/Caddyfile` | new (Caddy package also drops its default; ours replaces it) | TLS |
| `/usr/local/bin/dishnet-vpnd` | new | the binary |
| `/var/lib/dishnet/` (+ `dishnet.db` on first start) | new, `dishnet:dishnet 0750` | database |
| `/etc/apt/sources.list.d/caddy-stable.list` + keyring | new | Caddy repo |
| user/group `dishnet` | created | least privilege |
| **not changed** | sshd, DO cloud firewall, `/etc/wireguard/*.key`, VPN subnet/port, `wg-quick@wg0` state | — |

### Kernel/runtime state changed by `--apply`

* `table inet dishnet` loaded (default-deny for traffic entering from `wg0`).
  The stale `iptables FORWARD -i wg0 -o wg0 ACCEPT` rule stays loaded until
  the next `wg-quick` restart or reboot; it is overridden because any drop in
  our chain is final. Optional immediate flush (zero downtime):
  `iptables -D FORWARD -i wg0 -o wg0 -j ACCEPT`.
* `nftables.service` enabled (loads `/etc/nftables.conf` at boot, before `wg-quick`).
* `dishnet-vpnd` and `caddy` running; Caddy obtains the certificate within ~10 s.
* No peer is added (database empty), so **no customer-visible change**.

---

## 5. Apply — only on explicit approval

```bash
cd /root/wiregaurd
export DISHNET_BIN=/root/dishnet-vpnd DISHNET_DOMAIN=vpn.dishnetuganda.com DISHNET_ALLOW_ANY_ADMIN_IP=yes   # test phase: dashboard open to any IP (password + rate limit); set DISHNET_ADMIN_ALLOW=<ip> later
bash deploy/install.sh --apply 2>&1 | tee /root/install-$(date +%F).txt
```

Expected tail:

```
## 9. Start and validate
  API healthy
  nftables table 'dishnet' loaded
  wg0 still up (key/port untouched)

Next: create the first administrator:
  sudo -u dishnet DISHNET_DB=/var/lib/dishnet/dishnet.db dishnet-vpnd admin-create you@dishnet.example owner
Then open https://vpn.dishnetuganda.com/admin
```

Validation commands and expected output:

```bash
wg show wg0
# interface: wg0
#   public key: UBCUzaw/MppPOGdTq7FRm2ZGn+TsaTYR8MhtAgv6tVs=     ← unchanged
#   listening port: 51820                                          ← unchanged

sed -n '1,10p' /etc/wireguard/wg0.conf | grep -c PostUp
# 0

nft list table inet dishnet | head -12
# table inet dishnet {
#         chain forward {
#                 type filter hook forward priority filter; policy accept;
#                 iifname "wg0" goto vpn_from_peer
#                 oifname "wg0" goto vpn_to_peer
#         }
#         chain vpn_from_peer {
#                 ct state invalid drop
#                 ct state established,related accept
#                 counter packets 0 bytes 0 drop comment "dishnet default deny"
# ...

systemctl is-active dishnet-vpnd caddy nftables
# active
# active
# active

journalctl -u dishnet-vpnd -n 3 --no-pager
# ... level=INFO msg="hub converged" reason=reconcile peers=0 rules=0 routes=0
# ... level=INFO msg="dishnet-vpnd listening" addr=127.0.0.1:8080 interface=wg0 dry_run=false version=<sha>

curl -sI https://vpn.dishnetuganda.com/admin/login | head -1
# HTTP/2 200          (from an allow-listed IP; 403 from any other IP)

ps -o user,rss,cmd -C dishnet-vpnd
# dishnet  ~8000  /usr/local/bin/dishnet-vpnd serve

sudo -u dishnet DISHNET_DB=/var/lib/dishnet/dishnet.db dishnet-vpnd admin-create <you@dishnetuganda.com> owner
# Password (min 12 chars):
# created administrator <you@dishnetuganda.com> (owner)
```

Then sign in at `https://vpn.dishnetuganda.com/admin`, create one **test**
customer, generate a gateway code and a client code, and activate them with
two machines (for now with a plain WireGuard client rendering the JSON
config by hand; the Windows app arrives in Phase 3). Verify:

```bash
wg show wg0 | grep -E 'peer|allowed'
#   peer: <gateway key>   allowed ips: 10.20.0.17/32
#   peer: <client key>    allowed ips: 10.20.0.18/32
nft list chain inet dishnet vpn_from_peer | grep accept
#   ct state established,related accept
#   ip saddr 10.20.0.18 ip daddr 10.20.0.17 tcp dport { 3389 } accept comment "c1 default <gateway name>"
```

From the client: RDP to `10.20.0.17` connects; `ping 10.20.0.17` is dropped
(ICMP not in policy — expected); any other address is unreachable. Revoke the
client in the dashboard → `wg show` loses it within a second.

---

## 6. Rollback

Any time after step 5, as root, with the `<stamp>` printed by step 3/5:

```bash
bash /root/wiregaurd/deploy/rollback.sh /var/backups/dishnet/<stamp>
# # rolling back from /var/backups/dishnet/<stamp>
# removed nftables table 'dishnet'
# restored /etc/wireguard
# wg0.conf changed; restarting wg-quick@wg0 (brief VPN interruption)
# restored /etc/nftables.conf (pre-install)
# # rollback complete. wg status:
# interface: wg0 ... public key: UBCUzaw/... listening port: 51820
```

Result: original `wg0.conf` (with the PostUp rule) and the original firewall
state; `dishnet-vpnd` stopped and disabled; Caddy left running but
restorable (`systemctl disable --now caddy`). Packages and the `dishnet` user
remain (harmless). Full manual removal, if ever wanted:

```bash
systemctl disable --now dishnet-vpnd caddy nftables
rm -f /etc/systemd/system/dishnet-vpnd.service /etc/dishnet/dishnet-vpnd.env /etc/nftables.d/dishnet.nft /usr/local/bin/dishnet-vpnd
sed -i '/nftables.d\/\*.nft/d' /etc/nftables.conf
userdel dishnet; rm -rf /var/lib/dishnet
```

Emergency "just make the VPN behave as before" without the script:
`nft delete table inet dishnet && systemctl stop dishnet-vpnd` (10 s, no
interruption to existing tunnels).

---

## 7. Security test results (branch head, `go test -race -count=1 ./...`)

29/29 passed, 0 skipped, race detector on; also green in GitHub Actions
(run 1, which additionally runs the generated ruleset through `nft -c`).

| Package | Tests | What they prove |
|---|---|---|
| `provision` | `TestCustomersCannotReachEachOther` | no rule ever joins two customers' addresses; a hand-inserted cross-tenant policy row is ignored; cross-tenant policy creation is refused |
| | `TestActivationCodeIsSingleUse`, `TestUnauthorisedActivationIsRejected` | reuse, unknown, revoked, expired codes, bad keys, duplicate keys, device limit all rejected; no peer created |
| | `TestConcurrentActivationsGetUniqueAddresses` | 40 parallel activations → exactly 14 devices, 14 distinct addresses |
| | `TestRevocationRemovesPeerAndDeniesConfig` | peer and rules gone immediately; 403 `revoked`; address not recycled |
| | `TestSuspensionAndExpiryDropAllPeers` | suspension/expiry remove only that customer's peers; reactivation restores |
| | `TestRestartRecoveryRepopulatesEmptyHub` | fresh process over an empty kernel restores every peer and the identical firewall |
| | `TestProvisioningFailureIsRecordedAndRecovered` | netlink failure → failed job visible to admin → auto-recovered |
| | `TestSMBIsRefusedByDefault`, `TestModeBLANRoutingAndOverlap`, `TestNoSecretsInConfigOrAudit`, `TestActivationProvisionsPeerAndReturnsConfig`, `TestStatsFlowIntoDevices` | as named |
| `firewall` | `TestRenderGolden`, `TestRenderIsDefaultDenyAndSorted`, `TestRenderRejectsBadInput`, `TestRenderedFileParsesWithNft` | byte-exact ruleset, default deny, injection via interface/label refused, `nft -c` accepts |
| `api` | `TestActivateThenConfigAndRevocation`, `TestActivationRateLimit`, `TestActivateRejectsBadInput` | HTTP contract, 6th attempt → 429, unknown JSON fields → 400, no secrets in responses |
| `admin` | `TestLoginCSRFAndRoles`, `TestIPAllowlist` | wrong password 401, missing CSRF 403, viewer cannot write, allowlist 403, security headers |
| `auth`, `ipam` | 7 tests | code normalisation/hashing, argon2id, token uniqueness, `/28` arithmetic (14 per block, 15 blocks) |

Not yet proven (needs the first live apply): the real netlink and `nft -f`
code paths, Caddy certificate issuance. Step 5's validation commands cover
exactly those.

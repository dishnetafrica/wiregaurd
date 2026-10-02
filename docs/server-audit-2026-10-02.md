# Hub audit — 165.227.89.92 — 2026-10-02

Read-only audit supplied by DishNet (output of the §7 command set). Backup
`/root/wireguard-backup-2026-10-02.tgz` (mode 0600) confirmed.

## Findings

| Area | Observed | Consequence for deployment |
|---|---|---|
| OS / kernel | Ubuntu 24.04.5, kernel 6.8.0-142 | supported; WireGuard in-kernel |
| `wg0.conf` | `[Interface]` only: `10.20.0.1/24`, port 51820, `PostUp/PostDown iptables FORWARD -i wg0 -o wg0 ACCEPT`; **no `[Peer]` blocks** | exactly the expected shape; installer strips the two PostUp/PostDown lines and nothing else |
| Firewall backend | `iptables 1.8.10 (nf_tables)` — the PostUp rule lives in nftables `table ip filter` | our `table inet dishnet` coexists; a drop in our chain is final even while the old accept rule is still loaded |
| ufw | installed, **inactive** | no `ufw route allow` needed; installer skips it |
| nftables | package present, no `nftables.service` config | installer creates `/etc/nftables.conf` with the include |
| Forwarding | `ip_forward = 1` | ok |
| Listening | 22/tcp (sshd), 51820/udp, resolver on loopback only | **80 and 443 are free** for Caddy |
| Services | DO agents, cron, rsyslog, unattended-upgrades — nothing else | no conflicts |
| Memory | **458 MB RAM, no swap**, 296 MB available | do not build Go on this box; use the CI binary. Add a 1 GB swap file before installing (optional, reversible) |
| Disk | 8.7 GB, 6.8 GB free | fine |
| SSH | `PermitRootLogin yes`, `PasswordAuthentication yes` | **risk R6 confirmed** — see below |
| Interfaces | `eth0` public + DO anchor `10.10.0.5/16`; `eth1` VPC `10.136.0.2/16` | `10.10.0.0/16` and `10.136.0.0/16` do not overlap the VPN pool |
| DNS | `vpn.dishnetuganda.com A 165.227.89.92` (GoDaddy, TTL 600) | ready for Let's Encrypt once 80/443 are open in the DO cloud firewall |
| DO Cloud Firewall | not yet reported | must allow 22/tcp (admin IPs only), 51820/udp, 80/tcp, 443/tcp |

## Recommendations outside the installer (DishNet to do, not scripted —
each one can lock you out if done wrong)

1. **SSH hardening, in this order:** confirm key-based login works for a
   non-root sudo user → in the DO Cloud Firewall restrict 22/tcp to the admin
   IPs → then set `PasswordAuthentication no` and `PermitRootLogin
   prohibit-password` in `/etc/ssh/sshd_config.d/99-dishnet.conf` and
   `systemctl reload ssh` **while keeping an existing session open** to test.
2. **Swap (recommended on 458 MB):**
   `fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab`
3. **unattended-upgrades** is active: a kernel upgrade will reboot the box
   when DO applies it; the reconciler restores peers at boot, so this is safe
   but customers will see a short outage. Consider a maintenance window
   setting later.

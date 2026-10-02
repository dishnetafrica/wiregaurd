# VPN address plan

## 1. The arithmetic, verified

A prefix of length *n* holds 2^(32−n) addresses.

| Block | Addresses | Assignable to devices (policy below) | Blocks in `10.20.0.0/24` | Customer blocks after reserving one for infrastructure |
|---|---|---|---|---|
| `/29` | 8 | 6 | 32 | 31 |
| `/28` | 16 | **14** | 16 | **15** |
| `/27` | 32 | 30 | 8 | 7 |

Strictly, WireGuard does not need network or broadcast addresses: every peer
is reached through its own `/32` in the hub's cryptokey routing table, so all
16 addresses of a `/28` *could* be handed out. We deliberately **do not use
the first and last address of each block** anyway, because

* customers may later route the block from an office gateway (Mode B), where
  classic subnet rules apply, and
* it keeps the maths identical to what network engineers expect (14 per `/28`).

So, as DishNet stated: **`/28` = 14 devices per customer, 15 customers in the
existing `/24`**; `/29` = 6 devices, 31 customers.

## 2. Pilot plan (decided: `/28`)

```
10.20.0.0/24      pool "primary"  (existing, unchanged)
  10.20.0.0/28    reserved: hub 10.20.0.1, future monitoring/jump hosts
  10.20.0.16/28   customer block #1   (devices 10.20.0.17 – 10.20.0.30)
  10.20.0.32/28   customer block #2   (devices 10.20.0.33 – 10.20.0.46)
  …
  10.20.0.240/28  customer block #15
```

Each device gets a single `/32` from its customer's block. The hub's
server-side `AllowedIPs` for the device is exactly that `/32` (plus declared
office LAN subnets for a gateway), so a device cannot send from another
address — WireGuard drops it before the firewall is even consulted.

## 3. Growth beyond the `/24` (no migration of existing customers)

The allocator is **pool-aware**: `address_pools` is a table, not a constant.
When the primary pool is full the administrator adds a second pool; nothing
about existing customers changes.

| Pool | Prefix | `/28` blocks | Notes |
|---|---|---|---|
| primary | `10.20.0.0/24` | 15 | existing |
| pool-2 | `10.21.0.0/16` | 4 096 | first expansion, 57 000+ devices |
| pool-3… | `10.22.0.0/16`, … | 4 096 each | as needed |

What adding a pool requires on the hub — one line, no key or port change:

```
# wg0.conf [Interface]:  Address = 10.20.0.1/24, 10.21.0.1/16
```

(The hub address inside the new pool is optional — peers are routed by
`AllowedIPs`, not by the interface address — but having one makes `ping` and
diagnostics work. `dishnet-vpnd` adds the route for each pool to `wg0` at
start-up and will warn if the interface address is missing.)

Clients and gateways never carry a whole pool in their `AllowedIPs`, only the
specific addresses they are authorised for, so pool growth does not affect
configs already issued.

## 4. Office LAN subnets (Mode B)

Declared per gateway device. The API rejects a LAN subnet that

* overlaps any VPN pool,
* overlaps another customer's declared LAN, or
* is not RFC 1918.

Overlaps *within* one customer are allowed (two gateways, same LAN) but
flagged. Customers whose office LAN is a very common range (`192.168.0.0/24`,
`192.168.1.0/24`) will collide with other customers; those customers are
advised to use Mode A (server-only) or to renumber. Isolation does not depend
on uniqueness — the hub firewall only allows a client to reach *its own*
customer's gateway — but routing on the hub does: the kernel can hold only one
route per LAN prefix, so overlapping Mode B LANs across customers are refused.

## 5. Capacity planning

| Resource | $4 Droplet (1 vCPU, 512 MB) | Comment |
|---|---|---|
| Peers | hundreds | WireGuard state per peer is tiny. |
| Throughput | ~200–400 Mbit/s aggregate | far above a Starlink uplink; CPU-bound. |
| `dishnet-vpnd` | ~30 MB RAM | Go + SQLite. |
| Caddy | ~20 MB RAM | TLS termination. |

Upgrade trigger: sustained CPU > 60 % or more than ~50 concurrently active
devices; resize the Droplet in place (no re-addressing).

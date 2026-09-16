# Curfew 0.3.0

The biggest change since the first release: you can now identify the devices on
your network, see what they're doing, and control Curfew from a browser — with
a password protecting every action.

## New: seeing who has been using Curfew

Curfew now keeps a record of who has been controlling it, with where they
signed in from. Option `10` in the terminal, or the **Who's using Curfew** card
in the web panel.

For every sign-in it records when and from which address, along with every
change that was made. Wrong passwords, a second copy of Curfew being started on
the same machine, another Curfew panel found on your network, and a change to
your router's hardware address are all flagged as things worth a look.

**The attempted password is never recorded** — not in full, not hashed, not
truncated. Only that an attempt happened, and where it came from.

You can also **end someone else's session** without changing the password:
"Sign out everyone else" in the panel, or option `10` then `1` in the terminal.
They are signed out immediately.

Two more things it watches for, since they mean someone else is involved:

- **Someone else is throttling your devices right now.** Curfew watches ARP
  traffic for another machine intercepting your devices — the signature of a
  second throttling tool. It reports an address claimed by two machines, one
  machine claiming several addresses, and an address re-announced about 60
  times a minute. Curfew does all three of these itself while it works, so it
  is explicitly told its own hardware address and never reports its own
  activity as somebody else's.
- **Another Curfew panel on your network.** It checks port 8787 (or your
  `--web` port) about every five minutes, and on demand from option `10`.
- **Something impersonating your router.** Curfew never spoofs its own view of
  the gateway, so if that hardware address changes, something else has started
  answering ARP for your router.

### New: the defense fights back

Detection used to stop at a report. Now Curfew **defends by default**: when a
spoofer is found, it pins the real hardware address of your router and of each
affected device as a permanent kernel entry — a spoofer's replies for those
addresses are then ignored outright — and re-announces the true addresses to
the rest of the network. Pins are re-asserted on every scan, so a spoofer that
dislodges one is corrected within a scan interval.

Turning Curfew off removes every pin it created. The pins are listed in option
`10` and in the panel, and the defense can be switched off there too.

Honest limits: a faster spoofer can win rounds between scans; the defense
doesn't evict anyone (block their MAC in the router or change the Wi-Fi
password for that); and it trusts Curfew's own record of which address was
real — check the listed pins if you're in doubt.

## New: a web control panel

```
sudo curfew --web
```

Then open `http://<this machine>:8787` from any device on your network — your
phone, your laptop, from work over a VPN.

It shows every device, whether it's online, how much has been slowed for it,
and what it's been asking for — and it can grant full speed, cut a device off,
change one device's speed or the household speed, give everyone a break, or
stop Curfew.

**Every action requires your password.** Signed out, the only page reachable is
the login form. Sessions are 32 random bytes in an `HttpOnly`,
`SameSite=Strict` cookie, expire after 2 hours idle (12 hours total), and every
action carries a per-session token so a malicious page can't forge one.
Repeated wrong passwords are throttled per address.

> **Read this before using it from outside your home:** the panel speaks plain
> HTTP, and it runs as root and can cut your household's internet off. Do
> **not** forward the port from the internet. Put this machine on a VPN
> (Tailscale, WireGuard) or reach the panel through an SSH tunnel:
>
> ```
> ssh -L 8787:127.0.0.1:8787 you@home
> ```
>
> If you want real TLS, put Caddy or nginx in front and pass `--trust-proxy`.

## New: knowing your devices

Devices are identified by **MAC address**, so an exemption follows the device
even when your router hands it a different IP. Curfew now records, per device:

- the name it reports (`kid-ipad`), which often says what it is
- who made it, from the MAC-vendor list nmap already installs
- what kind of thing it looks like — phone, tablet, TV, printer, console
- when it was first ever seen, and when it was last online
- how much traffic has been slowed for it, and how long it's been blocked

Press `9` for the full list, including devices that aren't here right now.

### ⚠︎ Devices with a changing address

Modern phones and tablets use a **private Wi-Fi address** by default — a random
MAC that the device rotates. Any rule tied to such an address stops matching
the next time it reconnects.

Curfew detects these and marks them **"changing address"** rather than
pretending the setting will stick. To fix it, turn off "Private Wi-Fi Address"
(iOS) or "Randomized MAC" (Android) **for your home network only** in that
device's Wi-Fi settings.

## New: seeing which sites are being asked for

For a device being slowed, Curfew can show the sites it's looking up —
`youtube.com`, `cdn.jsdelivr.net` — which is as close to "what are they
actually doing" as you can get when everything is HTTPS. It works because ARP
spoofing already routes that device's traffic through this machine. Option `5`
in the terminal, or next to each device in the web panel.

Install `tcpdump` to enable it.

Two honest limits: only devices being *slowed* are visible (an exempt device's
traffic doesn't pass through here), and a device using DNS-over-HTTPS won't
show up at all. It shows sites, never page contents.

## New: more control

- **`8`** — a different speed for one device, or cut it off entirely.
- **`3`** — bedtime hours per weekday: `weekends 22:00-09:00` can sit alongside
  `mon-fri 20:00-07:00`. Add as many windows as you like.
- Per-device traffic figures in the dashboard, not just household totals.

## Security

- **Passwords are now PBKDF2-HMAC-SHA256** with a random salt (600,000
  iterations), replacing a single unsalted SHA-256 round. The old scheme was
  fine for a local password; it isn't for one guarding remote control of your
  network. **Existing passwords keep working** and are upgraded automatically
  the first time you log in.
- **`--passwd`** replaces every saved password, for when you want to rotate it.
- Minimum password length is now 8 characters.
- A second copy of Curfew now refuses to start instead of fighting the first
  one for control of the `tc` rules and the ARP table.

## Fixed

These were real bugs in 0.2.0, not polish:

- **Full speed was capped at 100 Mbit for the whole house.** The "fast lane"
  had a hardcoded 100 Mbit ceiling, so on any faster connection everything —
  including you and every exempt device — was silently limited. It now uses
  the interface's real link speed.
- **IPv6 bypassed throttling silently.** ARP spoofing is IPv4-only, so a
  dual-stack device could reach the internet at full speed while Curfew
  displayed it as "slowed down". Curfew now detects this and tells you plainly
  on the dashboard, rather than lying. (Closing it properly needs NDP/RA
  forgery, which isn't implemented — turning IPv6 off on your router is the
  fix.)
- **IP forwarding was turned off on exit regardless of your system's setting.**
  If you had it enabled for Docker, a software router, or anything else,
  Curfew clobbered it. The original value is now saved and restored.
- **Exempt devices could leak an exemption.** The MAC cache never expired and
  the online list only ever grew, so when a router reassigned a DHCP lease to a
  different device, the new device could inherit the old one's full-speed
  exemption. MACs are now re-resolved after 60 seconds.
- **Departed devices kept poisoning ARP forever.** A device that left the
  network kept its `arpspoof` running, telling your router that its IP lived at
  this machine — breaking whatever device got that IP next. Devices are now
  released after they've been missing for a couple of minutes.
- **`pkill -f arpspoof` killed your own `arpspoof` sessions too**, not just
  Curfew's. Teardown now only touches processes Curfew started.
- **Cleanup could fail halfway and leave the network broken.** ARP restoration
  is now failure-safe, retries on a second Ctrl+C, and is idempotent.
- **Two of the speed options displayed the same label**, so "only a little
  slow" looked identical to the harshest setting.
- **Unknown command-line flags were silently ignored** — a typo'd `--rate`
  would just be dropped. They're now rejected with a message, and there's
  proper `--help`.

## Packaging

The Linux download is now a **statically linked binary** with no libc
requirement. Previously the released binary needed a glibc as new as whatever
machine built it, so on older distros it failed to start with a confusing
`GLIBC_2.xx not found`. The static build runs anywhere on x86_64 Linux —
including Debian stable, older Ubuntu, and Raspberry Pi OS.

## Install

```
curl -fsSL https://raw.githubusercontent.com/Xer0bit/curfew/master/setup.sh | bash
```

Verify the download if you like:

```
sha256sum -c curfew-linux-x86_64.sha256
```

Other architectures (including Raspberry Pi) still build from source:

```
git clone https://github.com/Xer0bit/curfew
cd curfew
cargo build --release
sudo ./target/release/curfew
```

## Upgrading from 0.2.0

Nothing to do. Settings in `/etc/curfew` — your full-speed list, nicknames, and
bedtime hours — are carried over untouched, and an existing bedtime window
keeps working in the new format. Your password upgrades itself to the stronger
hashing the next time you log in.

Optional: `sudo apt install tcpdump` to enable the site log.

## Known limitations

- **IPv6 isn't throttled** — detected and reported, not yet prevented.
- **Site visibility is DNS only** — encrypted DNS bypasses it.
- **Randomised MAC addresses can't be reliably identified** — detected and
  flagged, but the fix belongs on the device.
- **The web panel has no TLS of its own** — put it behind a VPN, a tunnel, or a
  reverse proxy.
- **The Windows backend remains the least tested** — it can't be
  cross-compiled here, so it still needs real-hardware validation.

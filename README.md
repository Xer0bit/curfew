<p align="center">
  <img src="assets/logo.svg" width="120" alt="Curfew" />
</p>

<h1 align="center">Curfew</h1>
<p align="center"><strong>⚠︎ Hello HUMANS, it most powerful wifi Hijacking tool written in RUST follow the setup instructions get full speed of your internet to you ⚠︎</strong></p>
<p align="center"><strong>Give your household's network a bedtime.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white" alt="macOS">
  <img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/Raspberry%20Pi-A22846?logo=raspberrypi&logoColor=white" alt="Raspberry Pi">
</p>

<p align="center">
  Throttle every device on your Wi-Fi to a crawl, and grant full speed only to who you choose.<br>
  One binary. No app, no router firmware, no cloud account.
</p>

---

```
$ sudo curfew

Curfew is on  ● watching your network (checked 14 times)
No bedtime hours set — internet stays slowed all the time.
----------------------------------------------------------------
192.168.1.42     you                     full speed
192.168.1.27     Kid's iPad              slowed right down     2.4MB
192.168.1.144    aa:bb:cc:dd:ee:ff       no internet           811KB
Data slowed so far: 4.2MB · Data at full speed: 1.1GB
----------------------------------------------------------------
1) Give a device full speed
2) Take full speed away from a device
3) Set bedtime hours (when to slow the internet)
4) Give a device a nickname
5) See what's been happening
6) Change how slow the internet is
7) Give everyone full speed for a while
8) Change one device's speed, or block it
9) See every device you've had (and when)
10) See who's been using Curfew
0) Stop Curfew (put everyone back to normal)
----------------------------------------------------------------
Choose an option:
```

## Install

### Linux

**Quick install (no repo clone needed)** — downloads a prebuilt binary:

```
curl -fsSL https://raw.githubusercontent.com/Xer0bit/curfew/master/setup.sh | bash
```

Prebuilt binaries currently cover Linux `x86_64` only. For other
architectures (e.g. Raspberry Pi), build from source:

```
git clone https://github.com/Xer0bit/curfew
cd curfew
cargo build --release
sudo ./target/release/curfew
```

The first `sudo` run installs itself to `/usr/local/bin/curfew` automatically.
Every run after that, from anywhere, is just `sudo curfew`.

### macOS

No prebuilt binary yet — the same `setup.sh` builds from source (installs
Rust via `rustup` if needed):

```
curl -fsSL https://raw.githubusercontent.com/Xer0bit/curfew/master/setup.sh | bash
```

Needs Homebrew (for `nmap` and `dsniff`, which the script installs for you).

### Windows

No built-in equivalent of Linux `tc` or macOS `dnctl`/`pfctl`, so the Windows
build depends on two third-party drivers: **[Npcap](https://npcap.com)** (ARP
spoofing) and **[WinDivert](https://reqrypt.org/windivert.html)** (traffic
shaping). Both need a one-time manual install (they show their own
installer/license prompts). From an elevated PowerShell:

```
irm https://raw.githubusercontent.com/Xer0bit/curfew/master/setup.ps1 | iex
```

The script checks for both drivers, tells you exactly what to install if
they're missing, then builds from source and installs to
`C:\ProgramData\Curfew\curfew.exe`. **The Windows backend is newer and less
battle-tested than Linux** — if traffic shaping or ARP spoofing misbehaves,
that's the first place to look; please file an issue with what you saw.

## Compatibility

**Operating system:** Linux, macOS, and Windows. The throttling mechanism is
different on each, since none of the three expose a shared way to shape
another device's traffic:

| OS      | ARP spoofing         | Traffic shaping           |
|---------|-----------------------|----------------------------|
| Linux   | `arpspoof` (dsniff)   | `tc` (HTB)                 |
| macOS   | `arpspoof` (dsniff)   | `pfctl` + `dnctl` (dummynet) |
| Windows | `pnet` + Npcap driver | WinDivert driver (userspace token bucket) |

Linux is the original, most-tested implementation. macOS reuses the same
CLI-tool approach with OS-native equivalents. Windows is architecturally the
most different (no built-in shaping primitive at all) and needs the two
extra drivers above.

**Architecture:** any architecture Rust targets — `x86_64`, `aarch64`/arm64,
`armv7` — the binary has no architecture-specific code of its own; it only
needs the platform's required tools (below) to exist. Runs well on a
Raspberry Pi (`aarch64`/`armv7`) as a low-power always-on box on the network.

**Required tools:**

| Platform          | Command                                                |
|-------------------|----------------------------------------------------------|
| Debian / Ubuntu   | `apt install iproute2 nmap dsniff iputils-arping`         |
| Fedora / RHEL     | `dnf install iproute nmap dsniff iputils`                 |
| Arch Linux        | `pacman -S iproute2 nmap dsniff iputils`                  |
| macOS             | `brew install nmap dsniff`                                |
| Windows           | [Npcap](https://npcap.com), [WinDivert](https://reqrypt.org/windivert.html), `nmap` on `PATH` |
| *optional*        | `tcpdump` — only for seeing which sites devices ask for   |

**Network requirement:** the interface you select must be your machine's
actual station (client) Wi-Fi connection to your router — not a hotspot/AP
interface, monitor-mode interface, or a VPN/tunnel interface. Devices on
cellular data, a VPN, or a separate guest network/VLAN aren't reachable and
won't be affected.

**Licensing note:** Npcap and WinDivert are third-party drivers with their
own licenses (both free for this kind of open-source, non-commercial use;
see their sites for commercial redistribution terms). Curfew doesn't bundle
either — `setup.ps1` links you to the official installers.

## Use

```
sudo curfew
```

Set a password on first run and pick your Wi-Fi interface — both are
remembered, so every run after that is just `sudo curfew`.

Everything on the network is slowed automatically. Use the menu to shape it:

- **`1` / `2`** — give a device permanent full speed, or take it back.
  Exemptions are stored against the device's MAC address, so they survive the
  router handing the device a different IP next week.
- **`3`** — bedtime hours, with days: `weekends 22:00-09:00` can sit alongside
  `mon-fri 20:00-07:00`. Add as many windows as you need.
- **`6`** — how slow everyone else is, from "barely works" to "gentle".
- **`8`** — a different speed for one device, or cut it off entirely.
- **`7`** — a temporary full-speed break for everyone, which ends on its own.
- **`0`** or `Ctrl+C` — puts everyone back to normal and exits.

Every device gets its own shaping lane, so the dashboard can show per-device
traffic alongside the household totals. It redraws every couple of seconds,
so it's always showing current state.

### Command line

```
sudo curfew --help                         all options
sudo curfew --status                       saved settings, and whether it's running
sudo curfew --add-user                     add another password alongside the existing one
sudo curfew --passwd                       replace the saved password
sudo curfew --iface wlan0 --rate 1mbit     skip the questions (good for cron)
sudo curfew --web                          also serve the browser control panel
```

`--status` works without root, which makes it the easy way to check on a
headless box.

Only one copy can run at a time. A second `sudo curfew` reports which process
already holds the network rather than fighting it for control of the `tc`
rules and the ARP table — a fight the network loses.

## Seeing who has been using Curfew

Curfew keeps a record of who has been controlling it, so you can tell whether
someone else has been in here. Option `10` in the terminal shows it, and it
appears in the web panel as **Who's using Curfew**.

For every sign-in it records **when** and **from which address**, along with
every change that was made. Anything worth your attention is flagged:

| Recorded | Shown as an alert |
|---|---|
| Someone signed into the panel | no — listed with the address |
| Someone got the password wrong | **yes**, with how many attempts |
| A device was blocked, unblocked or re-rated | no — listed with who did it |
| Someone tried to start a second Curfew on this machine | **yes** |
| Another Curfew control panel found on your network | **yes** |
| Someone else is throttling your devices (ARP spoofing detected) | **yes** |
| Your router's hardware address changed | **yes** — see below |

**The attempted password is never recorded** — not in full, not hashed, not
truncated. A failed attempt is logged as a failure and the address it came
from, nothing more. An audit log that captured credentials would itself become
the most sensitive file on the machine.

### Ending someone else's session

If someone is signed into the panel and you'd rather they weren't, you can end
their session without changing the password:

- in the web panel, **Who's using Curfew** lists every signed-in session with
  its address; **Sign out everyone else** ends all of them at once;
- in the terminal, option `10` then `1` lets you pick one by number.

The person is signed out immediately. They can sign back in if they know the
password — if that's the problem you want solved, change it with
`sudo curfew --passwd`.

### Spotting someone else doing this

Three things that aren't you and aren't your password:

**Someone else is throttling devices right now.** This is the direct check:
Curfew watches the ARP traffic on your network for another machine
intercepting your devices, which is the signature of a second throttling tool.
It looks for three things:

| Seen on the wire | What it means |
|---|---|
| One IP claimed by two different machines | Something is intercepting that device's traffic |
| One machine claiming several IPs | It's impersonating several devices at once |
| One address re-announced ~60×/minute | A tool repeating itself to stay ahead of the real device |

Curfew does all three of these itself while it works, so it is explicitly told
its own hardware address and **never reports its own activity as someone
else's**. What's left is another machine doing the same thing.

Option `10` then `4` shows who is claiming which address — an address listed
with two machines is one being interfered with. Install `tcpdump` to enable it.

### The defense: stopping them automatically

Detection alone leaves you reading a report. Curfew can also **fight back**,
and it's on by default.

When a spoofer is found, Curfew:

1. **Pins the real hardware address** of your router and of every device being
   interfered with, as a *permanent* entry in this machine's neighbour table.
   The kernel stops consulting the wire for those addresses entirely — a
   spoofer's replies are simply ignored.
2. **Re-announces the truth** to the rest of the network, because other
   devices' caches still hold the spoofer's lie until told otherwise.
3. **Re-asserts the pins on every scan**, so if the spoofer manages to
   dislodge one, it's corrected within a scan interval.

Turning Curfew off removes every pin it created — the kernel table is left
exactly as it found it. Pins are listed in option `10` and in the panel, so
you can check that what was pinned is genuinely your router's address.

**What it can't do, said plainly:**

- **It's a fight Curfew can lose.** A spoofer that re-asserts faster, or has
  root on the router, wins rounds. Between Curfew's scans, traffic can leak.
- **It doesn't evict them.** Their machine is still on your network. To
  actually remove them: block their MAC in your router, or change the Wi-Fi
  password.
- **It trusts Curfew's own observations.** The pinned address is the first one
  Curfew saw for that device. If an attacker poisoned that record first, the
  defense is confidently wrong — which is why the pins are listed for you to
  check.

**Another Curfew panel on the network.** If someone else has set up their own
Curfew on another machine, it will be listening on port 8787 (or whatever you
passed to `--web`). Curfew checks for that about every five minutes and records
anything it finds. You can also check on demand: option `10`, then `2`.

**Something impersonating your router.** Curfew sits in the middle of your
devices' traffic, but never of its own — so the hardware address this machine
sees for your router is the real one. If that address changes, something else
has started answering ARP for your router: either a replacement router (which
settles after being reported once) or another machine intercepting your
traffic.

The record is kept in `access.log` in the config directory (root-only), and
trimmed to the most recent 500 events.

## The web panel

```
sudo curfew --web                 # http://<this machine>:8787
sudo curfew --web 0.0.0.0:9000    # a different address or port
```

The panel shows every device — what it is, whether it's online, how much has
been slowed for it, and which sites it's been asking for — and can grant full
speed, block a device, change one device's speed, change the household speed,
give everyone a break, or stop Curfew. It also shows who has been using the
panel and lets you end someone else's session — see
[Seeing who has been using Curfew](#seeing-who-has-been-using-curfew).

**Every action requires your password.** There is no unauthenticated way to
read or change anything; signed out, the only page you can reach is the login
form. Sessions are 32 random bytes in an `HttpOnly`, `SameSite=Strict`
cookie, they expire after 2 hours idle (12 hours total), and every action
carries a per-session token so a malicious page can't forge one. Repeated
wrong passwords are throttled per address. Passwords are stored as
PBKDF2-HMAC-SHA256 with a random salt, so if the password file is ever read,
guessing is slow rather than instant.

### Reaching it from work

**Don't forward this port from the internet.** It runs as root and can cut
your household's internet off, and it speaks plain HTTP — a password over the
open internet is the only thing in the way.

Put the machine on a VPN (Tailscale, WireGuard, your router's built-in one),
or tunnel just this port over SSH:

```
ssh -L 8787:127.0.0.1:8787 you@home           # then browse 127.0.0.1:8787
sudo curfew --web 127.0.0.1:8787              # bind to localhost only
```

If you'd rather put a real reverse proxy (Caddy, nginx) in front of it for
TLS, pass `--trust-proxy`: cookie addresses are then taken from
`X-Forwarded-For` (only do this behind a proxy you control — otherwise any
client can forge its address) and session cookies are marked `Secure`.

## What Curfew knows about your devices

Devices are identified by **MAC address**, so an exemption follows the device
even when your router hands it a different IP next week. For each one Curfew
remembers:

- the name the device reports (`kid-ipad`), which often says what it is
- who made it, read from the MAC-vendor list nmap already installs
- what kind of thing it looks like — phone, tablet, TV, printer, console
- when it was first ever seen, and when it was last online
- how much traffic has been slowed for it, and how long it's been blocked

Option `9` lists everything, including devices that aren't here right now.

### ⚠︎ Devices with a changing address

Modern phones and tablets use a **private Wi-Fi address** by default — a
random MAC that the device changes, sometimes per network and sometimes
periodically. Any rule tied to such an address stops matching the next time
the device reconnects.

Curfew detects these and marks them **"changing address"** in the device list
rather than pretending the setting will stick. To fix it, turn off "Private
Wi-Fi Address" (iOS) or "Randomized MAC" (Android) **for your home network
only** in that device's Wi-Fi settings; after that it uses its real hardware
address and everything behaves. You can also give the device a nickname
(option `4`) or rely on its hostname, which stay stable either way.

## Seeing which sites are being asked for

On a device being slowed, Curfew can show the sites it's looking up —
`youtube.com`, `cdn.jsdelivr.net` — which is the closest thing to "what are
they actually doing" that survives HTTPS. It works because ARP spoofing
already routes that device's traffic through this machine. Option `5` shows
it in the terminal, and it appears next to each device in the web panel.

This needs `tcpdump` (`sudo apt install tcpdump`). Two honest limits: only
devices being slowed are visible, since an exempt device's traffic doesn't
pass through here; and a device using DNS-over-HTTPS or a hardcoded resolver
won't show up at all. It shows the sites asked for, never the pages
themselves — those are encrypted.

## Limitations

**IPv6 isn't slowed.** Curfew intercepts traffic with ARP spoofing, which is
IPv4-only. On a dual-stack network a throttled device can still reach the
internet at full speed over IPv6. Curfew detects this and says so on the
dashboard, rather than quietly showing a device as "slowed down" when it
isn't. The straightforward fix is to turn IPv6 off on your router. Closing it
from the device side needs NDP/RA forgery, which isn't implemented yet.

**Devices with a changing address can't be identified reliably.** See the
section above — a randomised MAC is detected and flagged, but the fix belongs
on the device.

**Site visibility is DNS only.** Encrypted DNS and pinned resolvers bypass it.
It answers "what is this device reaching for", not "what did it read".

**Don't `kill -9` it.** Curfew reverses ARP poisoning on its way out, so use
option `0` or `Ctrl+C`. A hard kill can orphan its `arpspoof` helpers, which
keep the network pointed at this machine with nothing left running to undo
it. If that happens: `sudo pkill arpspoof`, then run Curfew once and stop it
cleanly.

## Why

Parental controls that live in an app or a router UI are one factory reset
away from being gone. Curfew is a single password-gated binary you run when
you want the house offline and books open.

## Legal

Only run this on a network you own. It works by ARP spoofing — using it on a
network with other people's devices you don't control is a privacy violation
and likely illegal.

## License

MIT

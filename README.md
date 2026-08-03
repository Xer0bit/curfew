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

Curfew — wlan0 — ● watching (14 checks so far)
No curfew window set — throttling is always on.
----------------------------------------------------------------
192.168.1.42     you                     full speed
192.168.1.27     Kid's iPad              throttled at 10kbit
192.168.1.144    aa:bb:cc:dd:ee:ff       throttled at 10kbit
----------------------------------------------------------------
1) Give a device full speed
2) Revoke full speed from a device
3) Set or change the curfew schedule
4) Name a device
5) View activity log
0) Stop and restore everyone's internet
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

Set a password on first run. Pick your Wi-Fi interface. Everything else on
the network gets throttled automatically — pick option `1` to give a device
(yourself, your partner) permanent full speed, saved across restarts. `0` or
`Ctrl+C` restores everyone instantly. The dashboard refreshes itself every
couple of seconds, so it's always showing current state.

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

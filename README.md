<p align="center">
  <img src="assets/logo.svg" width="120" alt="Curfew" />
</p>

<h1 align="center">Curfew</h1>

<p align="center"><strong>Give your household's network a bedtime.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Raspberry%20Pi-A22846?logo=raspberrypi&logoColor=white" alt="Raspberry Pi">
  <img src="https://img.shields.io/badge/arch-x86__64%20%7C%20arm64%20%7C%20armv7-informational" alt="Architectures">
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

**Quick install (no repo clone needed)** — downloads a prebuilt binary:

```
curl -fsSL https://raw.githubusercontent.com/Xer0bit/curfew/master/setup_curfew.sh | bash
```

Prebuilt binaries currently cover Linux `x86_64` only. For other
architectures (e.g. Raspberry Pi), build from source:

```
git clone https://github.com/Xer0bit/curfew
cd curfew
cargo build --release
sudo ./target/release/curfew
```

Either way, the first `sudo` run installs itself to `/usr/local/bin/curfew`
automatically. Every run after that, from anywhere, is just:

```
sudo curfew
```

## Compatibility

**Operating system:** Linux only. Curfew shells out to `iproute2` (`tc`, `ip`),
`iw`, `nmap`, and `arpspoof`, and toggles `/proc/sys/net/ipv4/ip_forward` —
all Linux-specific. There is no Windows, macOS, or BSD support, and none
planned (those platforms have no equivalent `tc`/procfs interface).

**Architecture:** any architecture Rust targets — `x86_64`, `aarch64`/arm64,
`armv7` — since the binary has no architecture-specific code of its own; it
only needs the system tools below to exist for that platform. Developed and
tested on `x86_64`; runs well on a Raspberry Pi (`aarch64`/`armv7`) as a
low-power always-on box sitting on the network.

**Required tools** (install via your distro's package manager):

| Distro family    | Command                                                |
|-------------------|--------------------------------------------------------|
| Debian / Ubuntu   | `apt install iproute2 nmap dsniff iputils-arping`       |
| Fedora / RHEL      | `dnf install iproute nmap dsniff iputils`               |
| Arch Linux        | `pacman -S iproute2 nmap dsniff iputils`                |

Also needs `sha256sum` and `stty`, both part of GNU coreutils and present on
essentially every Linux install by default.

**Network requirement:** the interface you select must be your machine's
actual station (client) Wi-Fi connection to your router — not a hotspot/AP
interface, monitor-mode interface, or a VPN/tunnel interface. Devices on
cellular data, a VPN, or a separate guest network/VLAN aren't reachable and
won't be affected.

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

//! Curfew: gives your household's network a bedtime. Every device is
//! throttled by default; you decide who's exempt.

mod accesslog;
mod arpwatch;
mod auth;
#[cfg(any(target_os = "windows", test))]
mod bucket;
mod capture;
mod colors;
mod defense;
mod devices;
mod dnswatch;
mod install;
mod inventory;
mod ipv6;
mod lock;
mod network;
mod oui;
mod paths;
mod random;
mod rate;
mod schedule;
mod sha256;
mod spoof;
mod state;
mod stdin;
mod system;
mod tc;
mod ui;
mod watchdog;
mod web;
#[cfg(target_os = "windows")]
mod winshape;

use colors::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use inventory::Inventory;
use state::State;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use system::{enable_ip_forward, missing_dependencies, prompt, require_root};

/// Wall-clock seconds since the epoch. Used for the device history, which has
/// to survive restarts and so can't use a monotonic clock.
fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How often the background thread re-scans the network.
const SCAN_INTERVAL_SECS: u64 = 15;

/// How many consecutive scans a managed device may be missing before Curfew
/// stops managing it. At [`SCAN_INTERVAL_SECS`] this is two minutes — long
/// enough that a device merely asleep isn't dropped (which would let it come
/// back at full speed), short enough that a device that has genuinely left
/// doesn't keep its ARP poison in place for long.
const RELEASE_AFTER_MISSES: u32 = 8;

const USAGE: &str = "\
Curfew - give your household's network a bedtime.

Everything on your Wi-Fi is slowed down; you choose who gets full speed.

Usage:
  sudo curfew [options]

Options:
  --iface <name>     Wi-Fi interface to manage (asked once, then remembered)
  --rate <speed>     How slow everyone else should be
  --web [address]    Also serve a control panel in a browser (default
                      port: 8787). Reach it over a VPN or ssh tunnel.
  --trust-proxy      Trust X-Forwarded-For and mark cookies Secure. Only
                      use this behind your own reverse proxy.
  --status           Print the saved settings and exit (no root needed)
  --add-user         Add another password, keeping the existing one
  --passwd           Replace the saved password with a new one
  --no-install       Don't copy the binary to its install location
  -h, --help         Show this help
  -V, --version      Show the version

Speeds:
  10kbit    barely works - best for getting kids off screens (default)
  256kbit   slow, but still usable
  1mbit     only a little slow
  5mbit     gentle - barely noticeable

Run with no options for the interactive dashboard.

Seeing it from work:
  Don't forward this port from the internet - it runs as root and can cut
  your household's internet off. Put this machine on a VPN (Tailscale,
  WireGuard) or reach the panel through an SSH tunnel:

      ssh -L 8787:127.0.0.1:8787 you@home   # then browse 127.0.0.1:8787
";

/// How many scan cycles between checks for another control panel on the
/// network. That check is a port scan, so it runs on a slow cadence rather
/// than every cycle; at [`SCAN_INTERVAL_SECS`] this is about five minutes.
const PANEL_CHECK_EVERY: u32 = 20;

/// What the command line asked us to do.
enum Command {
    Run(Args),
    AddUser,
    Passwd,
    Status,
    Help,
    Version,
}

/// Options that only apply to a normal run.
#[derive(Default)]
struct Args {
    iface: Option<String>,
    rate: Option<String>,
    no_install: bool,
    /// `Some(address)` when `--web` was given.
    web: Option<String>,
    trust_proxy: bool,
}

fn parse_args(argv: &[String]) -> Result<Command, String> {
    let mut args = Args::default();
    let mut add_user = false;
    let mut passwd = false;
    let mut status = false;

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        // `--flag=value` is split up front so both spellings work.
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (arg, None),
        };

        match name {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--add-user" => add_user = true,
            "--passwd" => passwd = true,
            "--status" => status = true,
            "--no-install" => args.no_install = true,
            "--trust-proxy" => args.trust_proxy = true,
            // Unlike the other valued options, `--web` may stand alone: a
            // bare `--web` means "serve on the default port".
            "--web" => {
                args.web = Some(match inline {
                    Some(value) => value,
                    None => match argv.get(i + 1) {
                        Some(next) if !next.starts_with('-') => {
                            i += 1;
                            next.clone()
                        }
                        _ => format!("0.0.0.0:{}", web::DEFAULT_PORT),
                    },
                });
            }
            "--iface" | "--rate" => {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        i += 1;
                        argv.get(i)
                            .cloned()
                            .ok_or_else(|| format!("{name} needs a value"))?
                    }
                };
                if name == "--rate" {
                    if !rate::is_throttle_rate(&value) {
                        return Err(format!(
                            "unknown speed {value:?} — try one of: {}",
                            rate::CHOICES
                                .iter()
                                .map(|c| c.key)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    args.rate = Some(value);
                } else {
                    args.iface = Some(value);
                }
            }
            other => return Err(format!("unknown option {other:?}")),
        }
        i += 1;
    }

    // Order matters: `--status` must work without root or a password, and
    // `--add-user`/`--passwd` authenticate separately.
    if add_user {
        Ok(Command::AddUser)
    } else if passwd {
        Ok(Command::Passwd)
    } else if status {
        Ok(Command::Status)
    } else {
        Ok(Command::Run(args))
    }
}

/// Asks, in plain words, how slow the other devices should be. Only ever
/// shown once (the answer is remembered).
fn ask_rate_friendly() -> String {
    println!();
    println!("{BOLD}How slow should everyone else's internet be?{RESET}");
    for (i, key) in rate::SETUP_CHOICES.iter().enumerate() {
        let description = rate::menu_label(key);
        let note = if i == 0 { " (recommended)" } else { "" };
        println!("  {BOLD}{}{RESET}) {description}{DIM}{note}{RESET}", i + 1);
    }
    let choice = prompt(&format!(
        "{CYAN}Type a number and press Enter (or just Enter for the recommended one): {RESET}"
    ));
    match choice.trim().parse::<usize>() {
        Ok(n) if n >= 1 && n <= rate::SETUP_CHOICES.len() => rate::SETUP_CHOICES[n - 1].to_string(),
        _ => rate::DEFAULT_KEY.to_string(),
    }
}

/// Reports the saved configuration without needing root. Handy from a script
/// or a cron job, and the quickest way to check whether Curfew is running.
fn print_status() -> i32 {
    println!("curfew {}", env!("CARGO_PKG_VERSION"));

    match lock::running_pid() {
        Some(pid) => println!("running:   yes (process {pid})"),
        None => println!("running:   no"),
    }
    match paths::load_setting("iface") {
        Some(iface) => println!("wifi:      {iface}"),
        None => println!("wifi:      not set up yet"),
    }
    match paths::load_setting("rate") {
        Some(rate) => println!("speed:     {} ({rate})", rate::friendly(&rate)),
        None => println!("speed:     not set up yet"),
    }
    match schedule::load() {
        Some(schedule) => {
            let state_word = if schedule::is_active(&Some(schedule.clone())) {
                "on now"
            } else {
                "off now"
            };
            println!("bedtime:   {state_word}");
            for window in &schedule.windows {
                println!("             {}", window.describe());
            }
        }
        None => println!("bedtime:   none - slowed down all the time"),
    }
    println!("full speed: {} device(s)", state::load_allowed().len());
    0
}

/// Decides which managed devices to stop managing: those that have been
/// missing from [`RELEASE_AFTER_MISSES`] scans in a row.
///
/// `missed` is updated in place, and a device that reappears has its count
/// reset — so a device that is merely asleep is never dropped.
fn devices_to_release(
    managed: &[String],
    found: &[String],
    missed: &mut HashMap<String, u32>,
) -> Vec<String> {
    let mut vanished = Vec::new();
    for ip in managed {
        if found.contains(ip) {
            missed.remove(ip);
            continue;
        }
        let misses = missed.entry(ip.clone()).or_insert(0);
        *misses += 1;
        if *misses >= RELEASE_AFTER_MISSES {
            vanished.push(ip.clone());
        }
    }
    for ip in &vanished {
        missed.remove(ip);
    }
    vanished
}

/// Watches the network for devices and either throttles them or, if their MAC
/// is exempt, notes them as full-speed. Runs until the process exits.
#[allow(clippy::too_many_arguments)]
fn spawn_monitor(
    iface: String,
    gateway: String,
    subnet: String,
    my_ip: String,
    state: Arc<Mutex<State>>,
    inventory: Arc<Mutex<Inventory>>,
    panel_port: u16,
) {
    thread::spawn(move || {
        let mut curfew_active = true;
        // Remembered so the IPv6 warning is logged when it appears, not on
        // every single scan.
        let mut known_bypass: Vec<String> = Vec::new();
        // Converts the kernel's cumulative lane counters into per-device
        // deltas; they reset whenever the shaping tree is rebuilt.
        let mut traffic = tc::TrafficTracker::default();
        // Watches the gateway's hardware address for a change, which is what
        // something else impersonating the router looks like from here.
        let mut gateway_guard = watchdog::GatewayGuard::default();
        // Other panels already reported, so a persistent one is announced once
        // rather than every few minutes.
        let mut known_panels: Vec<String> = Vec::new();
        let mut panel_checks: u32 = 0;

        loop {
            {
                let mut st = devices::lock_state(&state);
                st.scan_count += 1;
            }

            // A break (option 7) grants full speed to everyone until its time
            // is up; expiring it here means the very next scan re-throttles.
            let (sched, paused) = {
                let mut st = devices::lock_state(&state);
                let paused = match st.pause_until {
                    Some(until) if std::time::Instant::now() < until => true,
                    Some(_) => {
                        st.pause_until = None;
                        false
                    }
                    None => false,
                };
                (st.schedule.clone(), paused)
            };
            let active = schedule::is_active(&sched) && !paused;

            if active != curfew_active {
                curfew_active = active;
                let msg = if active {
                    "Slowing resumed."
                } else if paused {
                    "Break started - everyone has full speed for now."
                } else {
                    "Bedtime hours ended - everyone has full speed."
                };
                state::log_event(&state, msg);
            }

            if !active {
                // Batched: every shaping rebuild reconfigures the whole tree.
                let throttled = devices::lock_state(&state).devices.clone();
                devices::release(&iface, &throttled, &state);
                known_bypass.clear();
                let mut st = devices::lock_state(&state);
                st.exempt_online.clear();
                st.ipv6_bypass.clear();
                st.last_scan_devices = 0;
                drop(st);
                state::log_event(
                    &state,
                    "Checked network: curfew paused, everyone full speed.",
                );
                thread::sleep(Duration::from_secs(SCAN_INTERVAL_SECS));
                continue;
            }

            // Scan the whole subnet. Excluding devices we already manage
            // wouldn't save any work — nmap scans the subnet either way — and
            // it would blind us to devices that have left, which is how
            // orphaned ARP spoofing used to pile up.
            let exclude = vec![my_ip.clone(), gateway.clone()];

            match network::scan_devices(&subnet, &exclude) {
                Ok(found) => {
                    let found_ips: Vec<String> = found.iter().map(|d| d.ip.clone()).collect();

                    // One neighbour-table read per scan, not per device.
                    ipv6::prime_neighbour_table(&iface);
                    let neighbours = ipv6::neighbours(&iface);

                    // Everything not seen this time is offline as of now, so
                    // the inventory's "last seen" stays truthful.
                    if let Ok(mut inv) = inventory.lock() {
                        inv.mark_all_offline();
                    }

                    let mut exempt_now = Vec::new();
                    let mut bypass_now = Vec::new();
                    let mut to_throttle = Vec::new();

                    for device in &found {
                        // nmap usually reports the MAC itself, which saves a
                        // separate lookup and works before the kernel's
                        // neighbour table has warmed up.
                        let mac = match &device.mac {
                            Some(mac) => {
                                state::remember_mac(&state, &device.ip, mac);
                                mac.clone()
                            }
                            None => state::get_mac(&state, &iface, &device.ip),
                        };

                        // Record the sighting before deciding what to do with
                        // it, so the history covers exempt devices too.
                        let first_time = match inventory.lock() {
                            Ok(mut inv) => inv.seen(&mac, device.hostname.as_deref(), now_epoch()),
                            Err(_) => false,
                        };
                        if first_time {
                            let description = inventory
                                .lock()
                                .ok()
                                .and_then(|inv| inv.get(&mac).map(|r| r.label()))
                                .unwrap_or_else(|| mac.clone());
                            let ip = device.ip.clone();
                            state::log_event(
                                &state,
                                &format!("New device: {description} ({ip})"),
                            );
                        }

                        let is_allowed = devices::lock_state(&state).allowed_macs.contains(&mac);
                        if is_allowed {
                            exempt_now.push(device.ip.clone());
                            continue;
                        }

                        if ipv6::has_global(&ipv6::addresses_in(&neighbours, &mac)) {
                            bypass_now.push(device.ip.clone());
                        }
                        to_throttle.push(device.ip.clone());
                    }

                    // Batched, because each shaping rebuild reconfigures the
                    // whole tree.
                    devices::throttle_batch(&iface, &gateway, &to_throttle, &state);

                    // Attribute new traffic to each device, and count the time
                    // a blocked device has spent blocked.
                    {
                        let managed = devices::lock_state(&state).devices.clone();
                        let blocked: Vec<String> = {
                            let st = devices::lock_state(&state);
                            managed
                                .iter()
                                .filter(|ip| st.is_blocked(ip))
                                .cloned()
                                .collect()
                        };
                        let snapshot = tc::snapshot(&iface);
                        let deltas = traffic.deltas(&snapshot, &managed);
                        if let Ok(mut inv) = inventory.lock() {
                            for (ip, bytes) in deltas {
                                let mac = devices::lock_state(&state)
                                    .mac_of(&ip)
                                    .unwrap_or_default();
                                if mac.is_empty() {
                                    continue;
                                }
                                let blocked_secs = if blocked.contains(&ip) {
                                    SCAN_INTERVAL_SECS
                                } else {
                                    0
                                };
                                inv.add_traffic(&mac, bytes, blocked_secs);
                            }
                        }
                    }

                    // A managed device that has stopped appearing is probably
                    // gone for good — but could just be asleep, so it is only
                    // released after several scans in a row without it. Left
                    // alone, its `arpspoof` would keep telling the router that
                    // its IP lives at our MAC address, which breaks whatever
                    // device the router hands that IP to next.
                    let vanished = {
                        let mut st = devices::lock_state(&state);
                        let managed = st.devices.clone();
                        let mut missed = std::mem::take(&mut st.missed);
                        let vanished = devices_to_release(&managed, &found_ips, &mut missed);
                        st.missed = missed;
                        vanished
                    };
                    for ip in &vanished {
                        state::log_event(
                            &state,
                            &format!("{ip} left the network - no longer slowing it"),
                        );
                    }
                    devices::release(&iface, &vanished, &state);

                    // Only announce a device the first time we see it
                    // bypassing, so the log stays readable.
                    for ip in &bypass_now {
                        if !known_bypass.contains(ip) {
                            let mac = state::get_mac(&state, &iface, ip);
                            state::log_event(
                                &state,
                                &format!(
                                    "Warning: {ip} ({mac}) has IPv6, so it can reach the \
                                     internet at full speed. Curfew only slows IPv4."
                                ),
                            );
                        }
                    }
                    known_bypass = bypass_now.clone();

                    {
                        let mut st = devices::lock_state(&state);
                        st.exempt_online = exempt_now;
                        st.ipv6_bypass = bypass_now;
                        st.last_scan_devices = st.devices.len();
                    }

                    let throttled = devices::lock_state(&state).devices.len();
                    state::log_event(
                        &state,
                        &format!("Checked network: {throttled} device(s) throttled."),
                    );

                    // Persist what we learned. Small file, every scan, so a
                    // crash or power cut loses at most one interval of history.
                    if let Ok(inv) = inventory.lock() {
                        inv.save();
                    }

                    // Only keep site history for devices we still manage.
                    let managed_now = devices::lock_state(&state).devices.clone();
                    dnswatch::with_log(|log| log.retain_only(&managed_now));
                }
                Err(e) => state::log_event(&state, &format!("Scan failed: {e}")),
            }

            // Someone else impersonating the router shows up here as a changed
            // hardware address for the gateway, because this machine's own ARP
            // view is never spoofed by Curfew.
            match gateway_guard.observe(watchdog::gateway_mac(&iface, &gateway).as_deref()) {
                watchdog::GatewayObservation::Baseline(mac) => {
                    state::log_event(
                        &state,
                        &format!(
                            "Router hardware address is {mac} - Curfew will warn if it changes."
                        ),
                    );
                }
                watchdog::GatewayObservation::Changed { from, to } => {
                    state::log_event(
                        &state,
                        &format!(
                            "The router's hardware address changed ({from} to {to}) - \
                             something else may be intercepting traffic."
                        ),
                    );
                    accesslog::record(
                        accesslog::Kind::GatewayChanged,
                        accesslog::ACTOR_TERMINAL,
                        &format!("{from} -> {to}"),
                    );
                }
                _ => {}
            }

            // Look for another Curfew panel on the network. On a slow cadence,
            // because this is a port scan, and reported only when the set
            // changes so a panel that stays up isn't announced forever.
            panel_checks = panel_checks.wrapping_add(1);
            if panel_checks.is_multiple_of(PANEL_CHECK_EVERY) {
                if let Ok(found) = watchdog::scan_for_panels(&subnet, &my_ip, panel_port) {
                    for host in found.iter().filter(|h| !known_panels.contains(h)) {
                        state::log_event(
                            &state,
                            &format!(
                                "Another Curfew panel is running at {host}:{panel_port} - \
                                 someone else may be controlling devices."
                            ),
                        );
                        accesslog::record(
                            accesslog::Kind::OtherPanel,
                            accesslog::ACTOR_TERMINAL,
                            &format!("panel at {host}:{panel_port}"),
                        );
                    }
                    known_panels = found;
                }
            }

            // The defense: if the ARP watcher saw someone intercepting
            // traffic, pin the real addresses so the spoofer's replies are
            // ignored, and re-announce the truth to the rest of the network.
            //
            // Runs every scan while enabled, so a spoofer that dislodged a
            // pin is corrected within one scan interval.
            if defense::is_enabled() {
                let contested: Vec<(String, String)> = arpwatch::with_watcher(|watcher| {
                    watcher
                        .contested()
                        .iter()
                        .map(|binding| {
                            // The first MAC seen for an address is the real
                            // one: the spoofer is the one that turned up
                            // later.
                            (
                                binding.ip.clone(),
                                binding.macs.first().cloned().unwrap_or_default(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

                let gateway_mac = watchdog::gateway_mac(&iface, &gateway);
                let pins = defense::plan(&gateway, gateway_mac.as_deref(), &contested);
                let fresh = defense::enable(&iface, pins);

                for pin in &fresh {
                    state::log_event(
                        &state,
                        &format!(
                            "Defense: pinned {} to {} ({}) - a spoofer's replies for it \
                             are now ignored",
                            pin.ip,
                            pin.mac,
                            pin.reason.label()
                        ),
                    );
                    accesslog::record(
                        accesslog::Kind::Defense,
                        accesslog::ACTOR_TERMINAL,
                        &format!("pinned {} to {}", pin.ip, pin.mac),
                    );
                }

                // Re-assert what's already pinned, in case the spoofer won a
                // round since the last scan.
                let reasserted = defense::maintain();
                if !reasserted.is_empty() {
                    state::log_event(
                        &state,
                        &format!("Defense: re-asserted {} pin(s)", reasserted.len()),
                    );
                }
            }

            thread::sleep(Duration::from_secs(SCAN_INTERVAL_SECS));
        }
    });
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_args(&argv) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{RED}{message}{RESET}");
            eprintln!("\n{USAGE}");
            std::process::exit(2);
        }
    };

    // These three need neither root, nor a terminal, nor the network.
    match command {
        Command::Help => {
            println!("{USAGE}");
            return;
        }
        Command::Version => {
            println!("curfew {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Command::Status => std::process::exit(print_status()),
        _ => {}
    }

    // `--status` must work without a terminal and without root, so it is
    // handled above. Everything below may need both.
    stdin::init();
    require_root();

    let missing = missing_dependencies();
    if !missing.is_empty() {
        eprintln!("{RED}Missing required tools: {}{RESET}", missing.join(", "));
        #[cfg(target_os = "linux")]
        eprintln!("Install them (Debian/Ubuntu): sudo apt install iproute2 nmap dsniff iputils-arping");
        #[cfg(target_os = "macos")]
        eprintln!("Install them: brew install nmap dsniff");
        #[cfg(target_os = "windows")]
        eprintln!("Install nmap from https://nmap.org/download.html and make sure it's on PATH.");
        std::process::exit(1);
    }

    // `--add-user` and `--passwd` only touch the password file, so they need
    // neither the lock nor the install step.
    match command {
        Command::AddUser => {
            auth::add_user();
            return;
        }
        Command::Passwd => {
            auth::reset_passwords();
            return;
        }
        _ => {}
    }

    let args = match command {
        Command::Run(args) => args,
        _ => unreachable!("handled above"),
    };

    // Refuse to start a second copy: two instances would fight over the same
    // qdisc and ARP table, and whichever exited first would restore the
    // network out from under the other.
    if let Err(message) = lock::acquire() {
        eprintln!("{RED}{message}{RESET}");
        std::process::exit(1);
    }

    // Trim the audit log to a bounded size now that we know we're the only
    // instance running.
    accesslog::compact();

    if !args.no_install {
        install::ensure_installed();
    }

    // A returning user has both of these saved from last time, so we skip
    // straight past every setup question.
    let saved_iface = paths::load_setting("iface");
    let saved_rate = paths::load_setting("rate");
    let first_time = saved_iface.is_none() && saved_rate.is_none();

    if first_time {
        println!();
        println!("{BOLD}{CYAN}Welcome to Curfew.{RESET}");
        println!("{DIM}This slows the internet down for every device on your Wi-Fi,{RESET}");
        println!("{DIM}except the ones you choose. Good for getting kids off screens.{RESET}");
        println!("{DIM}I'll ask a couple of quick questions once, then it runs by itself.{RESET}");
    }

    auth::authenticate();

    // Scheduled runs pass --iface/--rate to skip prompts; a returning
    // interactive user reuses last time's saved answers; only a genuine first
    // run asks anything.
    let iface = args
        .iface
        .or_else(|| saved_iface.filter(|s| network::list_wifi_interfaces().iter().any(|i| i == s)))
        .unwrap_or_else(network::select_interface);
    paths::save_setting("iface", &iface);

    let my_ip = network::get_own_ip(&iface);
    let gateway = network::get_gateway();
    let subnet = network::get_subnet(&iface);

    let rate = args
        .rate
        .or(saved_rate.filter(|r| rate::is_throttle_rate(r)))
        .unwrap_or_else(ask_rate_friendly);
    paths::save_setting("rate", &rate);

    if first_time {
        println!();
        println!("{GREEN}All set.{RESET}");
        println!("  This computer (you) will always have {GREEN}full speed{RESET}.");
        println!("  Everyone else on your Wi-Fi will be {YELLOW}slowed down{RESET}.");
        println!("  To give someone full speed, choose {BOLD}option 1{RESET} once the screen appears.");
        println!();
    }

    let state = Arc::new(Mutex::new(State::new(
        iface.clone(),
        gateway.clone(),
        rate.clone(),
    )));
    let inventory = Arc::new(Mutex::new(Inventory::load()));

    accesslog::record(
        accesslog::Kind::Started,
        accesslog::ACTOR_TERMINAL,
        &format!("on {iface}"),
    );

    {
        let state_for_handler = Arc::clone(&state);
        if let Err(e) = ctrlc::set_handler(move || {
            devices::cleanup(&state_for_handler);
        }) {
            eprintln!("{YELLOW}Warning: could not install the Ctrl+C handler ({e}).{RESET}");
            eprintln!("{YELLOW}Use option 0 to stop Curfew cleanly instead.{RESET}");
        }
    }

    enable_ip_forward();
    tc::reshape(&iface, &rate, &[]);

    // Watching DNS only makes sense while there's something to watch, and
    // only device traffic being routed through this machine is visible — so
    // this is best-effort and never blocks startup.
    if (args.web.is_some() || dnswatch::available()) && dnswatch::start(&iface) {
        println!("{DIM}Watching which sites devices ask for.{RESET}");
    }

    // Watch ARP for signs that something else is intercepting traffic. This
    // machine's own address is passed in so Curfew's own spoofing — which is
    // exactly the pattern being looked for — is never reported as somebody
    // else's activity.
    let my_mac = network::own_mac(&iface);
    if my_mac.is_none() {
        eprintln!(
            "{YELLOW}Couldn't read this machine's own hardware address, so Curfew \
             can't tell its own throttling apart from someone else's.{RESET}"
        );
    }
    if arpwatch::start(&iface, my_mac.as_deref(), |finding| {
        accesslog::record(
            accesslog::Kind::Spoofing,
            accesslog::ACTOR_TERMINAL,
            &finding.summary(),
        );
        arpwatch::report(finding);
    }) {
        println!("{DIM}Watching for someone else spoofing your network.{RESET}");
    }

    // The defense is on by default: if someone is throttling this network,
    // Curfew pins the real addresses so the spoofer's replies are ignored,
    // without waiting for anyone to be at the keyboard. It can be turned off
    // in the menu or the panel.
    if defense::available() {
        defense::enable(&iface, Vec::new());
        println!(
            "{DIM}Defense is on: if a spoofer is found, the real addresses will be \
             pinned automatically.{RESET}"
        );
    }

    // The port the watchdog should look for elsewhere on the network: ours if
    // we're serving a panel, otherwise the default a plain `--web` would use.
    let panel_port = args
        .web
        .as_deref()
        .map(web::port_of)
        .unwrap_or(web::DEFAULT_PORT);

    // The web panel runs on its own thread so the terminal menu keeps working.
    // It is opt-in: nothing listens on the network unless asked. The context is
    // kept here rather than moved into the thread, so the terminal menu can
    // also see and end live panel sessions.
    let web_context = if let Some(address) = args.web.clone() {
        if !auth::is_configured() {
            eprintln!("{RED}Set a password before enabling the web panel.{RESET}");
            std::process::exit(1);
        }
        let context = Arc::new(web::WebContext::new(
            Arc::clone(&state),
            Arc::clone(&inventory),
            iface.clone(),
            my_ip.clone(),
            args.trust_proxy,
        ));
        let context_for_server = Arc::clone(&context);
        std::thread::spawn(move || {
            if let Err(e) = web::serve(&address, context_for_server) {
                eprintln!("{RED}Web panel stopped: {e}{RESET}");
            }
        });
        Some(context)
    } else {
        None
    };

    println!("{DIM}Starting Curfew...{RESET}");

    spawn_monitor(
        iface.clone(),
        gateway,
        subnet,
        my_ip.clone(),
        Arc::clone(&state),
        Arc::clone(&inventory),
        panel_port,
    );

    ui::run_menu(
        &iface,
        &my_ip,
        &state,
        &ui::MenuContext {
            inventory: &inventory,
            web: web_context.as_ref(),
            panel_port,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_device_seen_every_scan_is_never_released() {
        let managed = ips(&["192.168.1.42"]);
        let mut missed = HashMap::new();
        for _ in 0..100 {
            assert!(devices_to_release(&managed, &managed, &mut missed).is_empty());
        }
        assert!(missed.is_empty(), "a present device shouldn't accrue misses");
    }

    #[test]
    fn a_briefly_absent_device_is_not_released() {
        // A phone asleep for a scan or two must keep its throttle, or it
        // would come back at full speed before the next scan could re-apply.
        let managed = ips(&["192.168.1.42"]);
        let mut missed = HashMap::new();
        for _ in 0..(RELEASE_AFTER_MISSES - 1) {
            assert!(devices_to_release(&managed, &[], &mut missed).is_empty());
        }
        assert_eq!(missed.get("192.168.1.42"), Some(&(RELEASE_AFTER_MISSES - 1)));
    }

    #[test]
    fn a_long_absent_device_is_released_exactly_once() {
        let managed = ips(&["192.168.1.42"]);
        let mut missed = HashMap::new();
        for _ in 0..RELEASE_AFTER_MISSES {
            devices_to_release(&managed, &[], &mut missed);
        }
        // Releasing again on the next scan would be redundant work.
        let managed_after = ips(&[]);
        assert!(devices_to_release(&managed_after, &[], &mut missed).is_empty());
        assert!(missed.is_empty(), "released devices shouldn't linger");
    }

    #[test]
    fn reappearing_resets_the_miss_count() {
        let managed = ips(&["192.168.1.42"]);
        let mut missed = HashMap::new();
        for _ in 0..(RELEASE_AFTER_MISSES - 1) {
            devices_to_release(&managed, &[], &mut missed);
        }
        devices_to_release(&managed, &managed, &mut missed);
        assert!(missed.is_empty());
        // And it must survive another near-miss run afterwards.
        for _ in 0..(RELEASE_AFTER_MISSES - 1) {
            assert!(devices_to_release(&managed, &[], &mut missed).is_empty());
        }
    }

    #[test]
    fn only_the_absent_devices_are_released() {
        let managed = ips(&["192.168.1.42", "192.168.1.7"]);
        let present = ips(&["192.168.1.7"]);
        let mut missed = HashMap::new();
        let mut released = Vec::new();
        for _ in 0..RELEASE_AFTER_MISSES {
            released = devices_to_release(&managed, &present, &mut missed);
        }
        assert_eq!(released, ips(&["192.168.1.42"]));
    }
}

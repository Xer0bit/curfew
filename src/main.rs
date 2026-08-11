//! Curfew: gives your household's network a bedtime. Every device is
//! throttled by default; you decide who's exempt.

mod auth;
mod colors;
mod devices;
mod install;
mod network;
mod paths;
mod schedule;
mod sha256;
mod spoof;
mod state;
mod stdin;
mod system;
mod tc;
mod ui;
#[cfg(target_os = "windows")]
mod winshape;

use colors::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use state::State;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use system::{enable_ip_forward, missing_dependencies, prompt, require_root};

const SCAN_INTERVAL_SECS: u64 = 15;

/// Remembers a small setup choice (the Wi-Fi to use, how slow to make things)
/// so returning users are never asked twice. Same config dir as the exempt
/// list and schedule.
fn load_saved(name: &str) -> Option<String> {
    std::fs::read_to_string(std::path::Path::new(paths::CONFIG_DIR).join(name))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_saved(name: &str, value: &str) {
    paths::ensure_dir();
    let _ = std::fs::write(std::path::Path::new(paths::CONFIG_DIR).join(name), value);
}

/// Asks, in plain words, how slow the other devices should be. Only ever
/// shown once (the answer is remembered).
fn ask_rate_friendly() -> String {
    println!();
    println!("{BOLD}How slow should everyone else's internet be?{RESET}");
    println!("  {BOLD}1{RESET}) Barely works  {DIM}— best for getting kids off screens (recommended){RESET}");
    println!("  {BOLD}2{RESET}) Slow, but still usable");
    let choice = prompt(&format!(
        "{CYAN}Type 1 or 2 and press Enter (or just press Enter for the recommended one): {RESET}"
    ));
    match choice.trim() {
        "2" => "256kbit".to_string(),
        _ => "10kbit".to_string(),
    }
}

fn parse_args() -> (Option<String>, Option<String>) {
    let mut iface = None;
    let mut rate = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iface" => {
                iface = args.get(i + 1).cloned();
                i += 2;
            }
            "--rate" => {
                rate = args.get(i + 1).cloned();
                i += 2;
            }
            _ => i += 1,
        }
    }
    (iface, rate)
}

/// Watches the network for devices and either throttles them or, if their MAC
/// is exempt, notes them as full-speed. Runs until the process exits.
fn spawn_monitor(
    iface: String,
    gateway: String,
    subnet: String,
    my_ip: String,
    state: Arc<Mutex<State>>,
) {
    thread::spawn(move || {
        let mut curfew_active = true;
        loop {
            {
                let mut st = state.lock().unwrap();
                st.scan_count += 1;
            }

            let sched = state.lock().unwrap().schedule.clone();
            let active = schedule::is_active(&sched);

            if active != curfew_active {
                curfew_active = active;
                let msg = if active {
                    "Curfew window started, throttling resumes."
                } else {
                    "Curfew window ended, full speed until next window."
                };
                state::log_event(&state, msg);
            }

            if !active {
                let throttled = state.lock().unwrap().devices.clone();
                for ip in throttled {
                    devices::unblock_device(&iface, &ip, &state);
                }
                state::log_event(
                    &state,
                    "Checked network: curfew paused, everyone full speed.",
                );
                thread::sleep(Duration::from_secs(SCAN_INTERVAL_SECS));
                continue;
            }

            let mut exclude = {
                let st = state.lock().unwrap();
                let mut e = st.devices.clone();
                e.extend(st.exempt_online.iter().cloned());
                e
            };
            exclude.push(my_ip.clone());
            exclude.push(gateway.clone());

            match network::scan_devices(&subnet, &exclude) {
                Ok(found) => {
                    for ip in found {
                        let mac = state::get_mac(&state, &iface, &ip);
                        let is_allowed = state.lock().unwrap().allowed_macs.contains(&mac);
                        if is_allowed {
                            state.lock().unwrap().exempt_online.push(ip.clone());
                            state::log_event(
                                &state,
                                &format!("{ip} ({mac}) is exempted, full speed"),
                            );
                        } else {
                            devices::throttle_device(&iface, &gateway, &ip, &state);
                        }
                    }
                    let throttled = state.lock().unwrap().devices.len();
                    state::log_event(
                        &state,
                        &format!("Checked network: {throttled} device(s) throttled."),
                    );
                }
                Err(e) => state::log_event(&state, &format!("Scan failed: {e}")),
            }

            thread::sleep(Duration::from_secs(SCAN_INTERVAL_SECS));
        }
    });
}

fn main() {
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

    install::ensure_installed();

    if std::env::args().any(|a| a == "--add-user") {
        auth::add_user();
        return;
    }

    let (iface_arg, rate_arg) = parse_args();

    // A returning user has both of these saved from last time, so we skip
    // straight past every setup question.
    let saved_iface = load_saved("iface");
    let saved_rate = load_saved("rate");
    let first_time = saved_iface.is_none() && saved_rate.is_none();

    if first_time {
        println!();
        println!("{BOLD}{CYAN}Welcome to Curfew.{RESET}");
        println!("{DIM}This slows the internet down for every device on your Wi-Fi,{RESET}");
        println!("{DIM}except the ones you choose. Good for getting kids off screens.{RESET}");
        println!("{DIM}I'll ask a couple of quick questions once, then it runs by itself.{RESET}");
    }

    auth::authenticate();

    // ponytail: cron/scheduled runs pass --iface/--rate to skip prompts; a
    // returning interactive user reuses last time's saved answers; only a
    // genuine first run asks anything.
    let iface = iface_arg
        .or_else(|| saved_iface.filter(|s| network::list_wifi_interfaces().iter().any(|i| i == s)))
        .unwrap_or_else(network::select_interface);
    save_saved("iface", &iface);

    let my_ip = network::get_own_ip(&iface);
    let gateway = network::get_gateway();
    let subnet = network::get_subnet(&iface);

    let rate = rate_arg
        .or(saved_rate)
        .unwrap_or_else(ask_rate_friendly);
    save_saved("rate", &rate);

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

    {
        let state_for_handler = Arc::clone(&state);
        ctrlc::set_handler(move || {
            devices::cleanup(&state_for_handler);
        })
        .expect("Error setting Ctrl+C handler");
    }

    enable_ip_forward();
    tc::rebuild_tc_base(&iface, &rate);

    println!("{DIM}Starting Curfew...{RESET}");

    spawn_monitor(
        iface.clone(),
        gateway,
        subnet,
        my_ip.clone(),
        Arc::clone(&state),
    );

    ui::run_menu(&iface, &my_ip, &rate, &state);
}

//! Curfew: gives your household's network a bedtime. Every device is
//! throttled by default; you decide who's exempt.

mod auth;
mod colors;
mod devices;
mod install;
mod network;
mod schedule;
mod state;
mod stdin;
mod system;
mod tc;
mod ui;

use colors::{BOLD, CYAN, DIM, GREEN, RED, RESET};
use state::State;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use system::{missing_dependencies, prompt, require_root};

const SCAN_INTERVAL_SECS: u64 = 15;

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
        eprintln!(
            "Install them (Debian/Ubuntu): sudo apt install iproute2 nmap dsniff iputils-arping"
        );
        std::process::exit(1);
    }

    install::ensure_installed();

    if std::env::args().any(|a| a == "--add-user") {
        auth::add_user();
        return;
    }

    auth::authenticate();

    let (iface_arg, rate_arg) = parse_args();

    // ponytail: cron/scheduled runs pass --iface/--rate to skip prompts; interactive
    // runs still get the wizard.
    let iface = iface_arg.unwrap_or_else(network::select_interface);
    let my_ip = network::get_own_ip(&iface);
    let gateway = network::get_gateway();
    let subnet = network::get_subnet(&iface);

    println!();
    println!("{BOLD}Interface{RESET} : {CYAN}{iface}{RESET}");
    println!("{BOLD}Self IP{RESET}   : {GREEN}{my_ip}{RESET}  (exempted, full speed)");
    println!("{BOLD}Gateway{RESET}   : {gateway}");
    println!("{BOLD}Subnet{RESET}    : {subnet}");
    println!();

    let rate = rate_arg.unwrap_or_else(|| {
        let rate_input = prompt(&format!(
            "{CYAN}Throttle rate for other devices (e.g. 10kbit) [default 10kbit]: {RESET}"
        ));
        if rate_input.is_empty() {
            "10kbit".to_string()
        } else {
            rate_input
        }
    });

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

    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    tc::rebuild_tc_base(&iface, &rate);

    println!("{GREEN}Self ({my_ip}) running at full speed.{RESET}");
    println!("{DIM}Monitoring {subnet} for devices every {SCAN_INTERVAL_SECS}s.{RESET}");
    println!();

    spawn_monitor(
        iface.clone(),
        gateway,
        subnet,
        my_ip.clone(),
        Arc::clone(&state),
    );

    ui::run_menu(&iface, &my_ip, &rate, &state);
}

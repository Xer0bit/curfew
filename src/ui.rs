//! A single always-current dashboard screen plus a numbered menu — no
//! scrolling log dump, no letter shortcuts to memorize.

use crate::colors::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use crate::devices::{cleanup, unblock_device};
use crate::schedule;
use crate::state::{display_name, get_mac, purge_exempt_online, save_allowed, save_names, State};
use crate::stdin;
use crate::system::{clear_screen, print_flush, prompt};
use crate::tc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const REFRESH_INTERVAL: Duration = Duration::from_millis(1500);

/// Plain-words version of the raw throttle rate, for the dashboard. A 60+
/// user shouldn't have to know what "10kbit" means.
fn friendly_rate(rate: &str) -> &'static str {
    match rate {
        "10kbit" => "slowed right down",
        "256kbit" => "slowed down",
        _ => "slowed down",
    }
}

fn format_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let n = n as f64;
    if n < KB {
        format!("{n:.0}B")
    } else if n < KB * KB {
        format!("{:.1}KB", n / KB)
    } else {
        format!("{:.1}MB", n / (KB * KB))
    }
}

/// 5x5 block glyph for each letter used in the "CURFEW" wordmark.
fn glyph(c: char) -> [&'static str; 5] {
    match c {
        'C' => [" ████", "█    ", "█    ", "█    ", " ████"],
        'U' => ["█   █", "█   █", "█   █", "█   █", " ███ "],
        'R' => ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
        'F' => ["█████", "█    ", "████ ", "█    ", "█    "],
        'E' => ["█████", "█    ", "████ ", "█    ", "█████"],
        'W' => ["█   █", "█   █", "█ █ █", "██ ██", "█   █"],
        _ => ["     ", "     ", "     ", "     ", "     "],
    }
}

/// Prints the "CURFEW" ASCII wordmark, built from `glyph`, plus a byline.
fn print_logo() {
    let mut rows: [String; 5] = Default::default();
    for c in "CURFEW".chars() {
        let g = glyph(c);
        for (row, line) in rows.iter_mut().zip(g) {
            row.push_str(line);
            row.push(' ');
        }
    }
    for row in &rows {
        println!("{BOLD}{CYAN}{row}{RESET}");
    }
    println!("{DIM}by xer0bit{RESET}");
    println!();
}

/// One row of the device table: display label, IP, and whether it's
/// throttled or exempt.
struct Row {
    label: String,
    ip: String,
    throttled: bool,
}

fn device_rows(state: &Arc<Mutex<State>>, iface: &str) -> Vec<Row> {
    let (throttled, exempt) = {
        let st = state.lock().unwrap();
        (st.devices.clone(), st.exempt_online.clone())
    };
    let mut rows: Vec<Row> = throttled
        .iter()
        .map(|ip| Row {
            label: display_name(state, iface, ip),
            ip: ip.clone(),
            throttled: true,
        })
        .collect();
    rows.extend(exempt.iter().map(|ip| Row {
        label: display_name(state, iface, ip),
        ip: ip.clone(),
        throttled: false,
    }));
    rows
}

fn draw_dashboard(state: &Arc<Mutex<State>>, iface: &str, my_ip: &str, rate: &str) {
    print_logo();
    let (scans, sched) = {
        let st = state.lock().unwrap();
        (st.scan_count, st.schedule.clone())
    };
    let pulse = if scans.is_multiple_of(2) {
        "●"
    } else {
        "○"
    };

    println!("{BOLD}{CYAN}Curfew is on{RESET}{DIM}  {GREEN}{pulse}{RESET}{DIM} watching your network (checked {scans} times){RESET}");
    match &sched {
        Some((start, end)) if schedule::is_active(&sched) => {
            println!("{DIM}Bedtime hours {start}-{end}: {RED}on now, internet is slowed{RESET}");
        }
        Some((start, end)) => {
            println!(
                "{DIM}Bedtime hours {start}-{end}: {GREEN}off now, everyone has full speed{RESET}"
            );
        }
        None => println!("{DIM}No bedtime hours set — internet stays slowed all the time.{RESET}"),
    }
    println!("{}", "-".repeat(64));

    println!(
        "{BOLD}{GREEN}{my_ip:<16}{RESET} you{:<24}{GREEN}full speed{RESET}",
        ""
    );

    let slowed = friendly_rate(rate);
    let rows = device_rows(state, iface);
    if rows.is_empty() {
        println!("{DIM}No other devices found yet — still looking...{RESET}");
    } else {
        for row in &rows {
            if row.throttled {
                println!(
                    "{RED}{:<16}{RESET} {:<24}{YELLOW}{slowed}{RESET}",
                    row.ip, row.label
                );
            } else {
                println!(
                    "{GREEN}{:<16}{RESET} {:<24}{GREEN}full speed (you allowed this one){RESET}",
                    row.ip, row.label
                );
            }
        }
    }
    let (throttled_bytes, fast_bytes) = tc::class_stats(iface);
    println!(
        "{DIM}Data slowed so far: {} · Data at full speed: {}{RESET}",
        format_bytes(throttled_bytes),
        format_bytes(fast_bytes)
    );
    println!("{}", "-".repeat(64));
}

fn draw_menu() {
    println!("{BOLD}1{RESET}) Give a device full speed");
    println!("{BOLD}2{RESET}) Take full speed away from a device");
    println!("{BOLD}3{RESET}) Set bedtime hours (when to slow the internet)");
    println!("{BOLD}4{RESET}) Give a device a nickname");
    println!("{BOLD}5{RESET}) See what's been happening");
    println!("{BOLD}0{RESET}) Stop Curfew (put everyone back to normal)");
    println!("{}", "-".repeat(64));
}

fn print_logs(state: &Arc<Mutex<State>>) {
    clear_screen();
    println!("{BOLD}{CYAN}What's been happening{RESET}");
    println!("{}", "-".repeat(64));
    let logs = state.lock().unwrap().logs.clone();
    if logs.is_empty() {
        println!("{DIM}Nothing yet.{RESET}");
    } else {
        for line in logs.iter().rev().take(40).rev() {
            println!("{DIM}{line}{RESET}");
        }
    }
    println!("{}", "-".repeat(64));
    prompt(&format!("{CYAN}Press Enter to go back...{RESET}"));
}

/// Picks a currently-throttled device and permanently exempts it (by MAC) so
/// it always gets full speed from now on, including after restarts.
fn allow_menu(iface: &str, state: &Arc<Mutex<State>>) {
    let devices = state.lock().unwrap().devices.clone();
    if devices.is_empty() {
        println!("\n{DIM}Nobody is being slowed down right now.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    println!("\n{BOLD}Which device should get full speed?{RESET}");
    for (i, ip) in devices.iter().enumerate() {
        let label = display_name(state, iface, ip);
        println!("  {CYAN}{}){RESET} {RED}{ip}{RESET}  ({label})", i + 1);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Type its number and press Enter (or just Enter to go back): {RESET}"
    ));
    if choice.is_empty() {
        return;
    }
    match choice.parse::<usize>() {
        Ok(n) if n >= 1 && n <= devices.len() => {
            let ip = devices[n - 1].clone();
            let mac = get_mac(state, iface, &ip);
            unblock_device(iface, &ip, state);
            let mut st = state.lock().unwrap();
            if !st.allowed_macs.contains(&mac) {
                st.allowed_macs.push(mac.clone());
                save_allowed(&st.allowed_macs);
            }
            st.exempt_online.push(ip.clone());
            drop(st);
            println!("{GREEN}Done. {ip} ({mac}) will always have full speed from now on.{RESET}\n");
        }
        _ => println!("{RED}That wasn't one of the numbers above.{RESET}\n"),
    }
    prompt("Press Enter to go back...");
}

/// Removes a previously-exempted MAC; it'll be throttled again next time it's
/// seen on the network (within one scan interval).
fn revoke_menu(state: &Arc<Mutex<State>>) {
    let allowed = state.lock().unwrap().allowed_macs.clone();
    if allowed.is_empty() {
        println!("\n{DIM}Nobody is on the full-speed list right now.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    println!("\n{BOLD}Which device should go back to being slowed down?{RESET}");
    for (i, mac) in allowed.iter().enumerate() {
        println!("  {CYAN}{}){RESET} {mac}", i + 1);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Type its number and press Enter (or just Enter to go back): {RESET}"
    ));
    if choice.is_empty() {
        return;
    }
    match choice.parse::<usize>() {
        Ok(n) if n >= 1 && n <= allowed.len() => {
            let mac = allowed[n - 1].clone();
            let mut st = state.lock().unwrap();
            st.allowed_macs.retain(|m| m != &mac);
            save_allowed(&st.allowed_macs);
            drop(st);
            purge_exempt_online(state, &mac);
            println!("{YELLOW}Done. {mac} will be slowed down again shortly.{RESET}\n");
        }
        _ => println!("{RED}That wasn't one of the numbers above.{RESET}\n"),
    }
    prompt("Press Enter to go back...");
}

/// Sets, changes, or clears the daily curfew window. With no window set,
/// throttling is always active (the original behavior).
fn schedule_menu(state: &Arc<Mutex<State>>) {
    let current = state.lock().unwrap().schedule.clone();
    println!();
    match &current {
        Some((s, e)) => println!("  Right now, bedtime hours are {s} to {e}."),
        None => println!("  {DIM}No bedtime hours set — the internet is slowed all the time.{RESET}"),
    }
    println!("{DIM}Use 24-hour time, like 20:00 for 8pm or 07:00 for 7am.{RESET}");
    let start = prompt("\nStart slowing the internet at (or just Enter to turn bedtime hours off): ");
    if start.is_empty() {
        state.lock().unwrap().schedule = None;
        schedule::clear();
        println!("{GREEN}Done. The internet will stay slowed all the time now.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    let end = prompt("Go back to full speed at: ");
    if !schedule::valid(&start) || !schedule::valid(&end) {
        println!("{RED}That didn't look like a time. Use 24-hour time like 20:00. Nothing changed.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    schedule::save(&start, &end);
    state.lock().unwrap().schedule = Some((start.clone(), end.clone()));
    println!("{GREEN}Done. Internet will be slowed from {start} to {end} each day.{RESET}\n");
    prompt("Press Enter to go back...");
}

/// Gives a currently-throttled device a friendly name (e.g. "Timmy's iPad")
/// shown everywhere instead of its raw MAC address.
fn name_menu(iface: &str, state: &Arc<Mutex<State>>) {
    let devices = state.lock().unwrap().devices.clone();
    if devices.is_empty() {
        println!("\n{DIM}No devices to nickname yet.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    println!("\n{BOLD}Which device do you want to nickname?{RESET}");
    for (i, ip) in devices.iter().enumerate() {
        let label = display_name(state, iface, ip);
        println!("  {CYAN}{}){RESET} {ip}  ({label})", i + 1);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Type its number and press Enter (or just Enter to go back): {RESET}"
    ));
    if choice.is_empty() {
        return;
    }
    let n: usize = match choice.parse() {
        Ok(n) if n >= 1 && n <= devices.len() => n,
        _ => {
            println!("{RED}That wasn't one of the numbers above.{RESET}\n");
            prompt("Press Enter to go back...");
            return;
        }
    };
    let name = prompt("Type a nickname (like Tim's iPad) and press Enter: ");
    if name.is_empty() {
        return;
    }
    let mac = get_mac(state, iface, &devices[n - 1]);
    let mut st = state.lock().unwrap();
    st.names.insert(mac, name.clone());
    save_names(&st.names);
    drop(st);
    println!("{GREEN}Done. That device is now called \"{name}\".{RESET}\n");
    prompt("Press Enter to go back...");
}

/// Redraws the dashboard every [`REFRESH_INTERVAL`] until the user actually
/// types something, so it never looks stale — pressing nothing still shows
/// live device/traffic state, not just a static screen waiting for Enter.
fn wait_for_command(iface: &str, my_ip: &str, rate: &str, state: &Arc<Mutex<State>>) -> String {
    loop {
        clear_screen();
        draw_dashboard(state, iface, my_ip, rate);
        draw_menu();
        print_flush(&format!("{CYAN}Choose an option: {RESET}"));
        if let Some(line) = stdin::read_line_timeout(REFRESH_INTERVAL) {
            return line;
        }
    }
}

pub fn run_menu(iface: &str, my_ip: &str, rate: &str, state: &Arc<Mutex<State>>) {
    loop {
        match wait_for_command(iface, my_ip, rate, state).as_str() {
            "1" => allow_menu(iface, state),
            "2" => revoke_menu(state),
            "3" => schedule_menu(state),
            "4" => name_menu(iface, state),
            "5" => print_logs(state),
            "0" => cleanup(state),
            "" => {}
            _ => {
                println!("{RED}Please type one of the numbers shown in the menu (0 to 5).{RESET}");
                prompt("Press Enter to go back...");
            }
        }
    }
}

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

    println!("{BOLD}{CYAN}Curfew{RESET}{DIM} — {iface} — {GREEN}{pulse}{RESET}{DIM} watching ({scans} checks so far){RESET}");
    match &sched {
        Some((start, end)) if schedule::is_active(&sched) => {
            println!("{DIM}Curfew window {start}-{end}: {RED}active now{RESET}");
        }
        Some((start, end)) => {
            println!(
                "{DIM}Curfew window {start}-{end}: {GREEN}paused, full speed for everyone{RESET}"
            );
        }
        None => println!("{DIM}No curfew window set — throttling is always on.{RESET}"),
    }
    println!("{}", "-".repeat(64));

    println!(
        "{BOLD}{GREEN}{my_ip:<16}{RESET} you{:<24}{GREEN}full speed{RESET}",
        ""
    );

    let rows = device_rows(state, iface);
    if rows.is_empty() {
        println!("{DIM}No other devices seen yet — first check runs shortly.{RESET}");
    } else {
        for row in &rows {
            if row.throttled {
                println!(
                    "{RED}{:<16}{RESET} {:<24}{YELLOW}throttled at {rate}{RESET}",
                    row.ip, row.label
                );
            } else {
                println!(
                    "{GREEN}{:<16}{RESET} {:<24}{GREEN}full speed (exempt){RESET}",
                    row.ip, row.label
                );
            }
        }
    }
    let (throttled_bytes, fast_bytes) = tc::class_stats(iface);
    println!(
        "{DIM}Traffic seen — throttled lane: {} · fast lane: {}{RESET}",
        format_bytes(throttled_bytes),
        format_bytes(fast_bytes)
    );
    println!("{}", "-".repeat(64));
}

fn draw_menu() {
    println!("{BOLD}1{RESET}) Give a device full speed");
    println!("{BOLD}2{RESET}) Revoke full speed from a device");
    println!("{BOLD}3{RESET}) Set or change the curfew schedule");
    println!("{BOLD}4{RESET}) Name a device");
    println!("{BOLD}5{RESET}) View activity log");
    println!("{BOLD}0{RESET}) Stop and restore everyone's internet");
    println!("{}", "-".repeat(64));
}

fn print_logs(state: &Arc<Mutex<State>>) {
    clear_screen();
    println!("{BOLD}{CYAN}Curfew — activity log{RESET}");
    println!("{}", "-".repeat(64));
    let logs = state.lock().unwrap().logs.clone();
    if logs.is_empty() {
        println!("{DIM}No activity yet.{RESET}");
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
        println!("\n{DIM}No devices are currently throttled.{RESET}\n");
        prompt("Press Enter to continue...");
        return;
    }
    println!();
    for (i, ip) in devices.iter().enumerate() {
        let label = display_name(state, iface, ip);
        println!("  {CYAN}{}){RESET} {RED}{ip}{RESET}  ({label})", i + 1);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Number to give full speed to (blank to cancel): {RESET}"
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
            println!("{GREEN}{ip} ({mac}) now always gets full speed.{RESET}\n");
        }
        _ => println!("{RED}Invalid choice.{RESET}\n"),
    }
    prompt("Press Enter to continue...");
}

/// Removes a previously-exempted MAC; it'll be throttled again next time it's
/// seen on the network (within one scan interval).
fn revoke_menu(state: &Arc<Mutex<State>>) {
    let allowed = state.lock().unwrap().allowed_macs.clone();
    if allowed.is_empty() {
        println!("\n{DIM}No one is exempted right now.{RESET}\n");
        prompt("Press Enter to continue...");
        return;
    }
    println!();
    for (i, mac) in allowed.iter().enumerate() {
        println!("  {CYAN}{}){RESET} {mac}", i + 1);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Number to remove from the exempt list (blank to cancel): {RESET}"
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
            println!("{YELLOW}{mac} will be throttled again once seen.{RESET}\n");
        }
        _ => println!("{RED}Invalid choice.{RESET}\n"),
    }
    prompt("Press Enter to continue...");
}

/// Sets, changes, or clears the daily curfew window. With no window set,
/// throttling is always active (the original behavior).
fn schedule_menu(state: &Arc<Mutex<State>>) {
    let current = state.lock().unwrap().schedule.clone();
    println!();
    match &current {
        Some((s, e)) => println!("  Current curfew window: {s} - {e}"),
        None => println!("  {DIM}No window set, throttling is always active.{RESET}"),
    }
    let start = prompt("\nStart time HH:MM (blank to clear the schedule): ");
    if start.is_empty() {
        state.lock().unwrap().schedule = None;
        schedule::clear();
        println!("{GREEN}Schedule cleared, throttling is always active now.{RESET}\n");
        prompt("Press Enter to continue...");
        return;
    }
    let end = prompt("End time HH:MM: ");
    if !schedule::valid(&start) || !schedule::valid(&end) {
        println!("{RED}Invalid time, expected 24-hour HH:MM (e.g. 20:00).{RESET}\n");
        prompt("Press Enter to continue...");
        return;
    }
    schedule::save(&start, &end);
    state.lock().unwrap().schedule = Some((start.clone(), end.clone()));
    println!("{GREEN}Curfew window set: {start} - {end}{RESET}\n");
    prompt("Press Enter to continue...");
}

/// Gives a currently-throttled device a friendly name (e.g. "Timmy's iPad")
/// shown everywhere instead of its raw MAC address.
fn name_menu(iface: &str, state: &Arc<Mutex<State>>) {
    let devices = state.lock().unwrap().devices.clone();
    if devices.is_empty() {
        println!("\n{DIM}No throttled devices to name.{RESET}\n");
        prompt("Press Enter to continue...");
        return;
    }
    println!();
    for (i, ip) in devices.iter().enumerate() {
        let label = display_name(state, iface, ip);
        println!("  {CYAN}{}){RESET} {ip}  ({label})", i + 1);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Number to name (blank to cancel): {RESET}"
    ));
    if choice.is_empty() {
        return;
    }
    let n: usize = match choice.parse() {
        Ok(n) if n >= 1 && n <= devices.len() => n,
        _ => {
            println!("{RED}Invalid choice.{RESET}\n");
            prompt("Press Enter to continue...");
            return;
        }
    };
    let name = prompt("Name: ");
    if name.is_empty() {
        return;
    }
    let mac = get_mac(state, iface, &devices[n - 1]);
    let mut st = state.lock().unwrap();
    st.names.insert(mac, name.clone());
    save_names(&st.names);
    drop(st);
    println!("{GREEN}Saved as \"{name}\".{RESET}\n");
    prompt("Press Enter to continue...");
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
                println!("{RED}Please enter a number from the menu.{RESET}");
                prompt("Press Enter to continue...");
            }
        }
    }
}

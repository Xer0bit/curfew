//! A single always-current dashboard screen plus a numbered menu — no
//! scrolling log dump, no letter shortcuts to memorize.

use crate::accesslog;
use crate::arpwatch;
use crate::colors::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use crate::defense;
use crate::devices::{
    cleanup, grant_full_speed as do_grant, lock_state, revoke_full_speed as do_revoke,
    set_device_mode, set_household_rate, set_pause,
};
use crate::dnswatch;
use crate::inventory::Inventory;
use crate::network;
use crate::rate;
use crate::schedule::{self, DaySet, Schedule, Window};
use crate::state::{display_name, get_mac, save_names, DeviceMode, State};
use crate::stdin;
use crate::system::{clear_screen, print_flush, prompt};
use crate::tc;
use crate::watchdog;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REFRESH_INTERVAL: Duration = Duration::from_millis(1500);
const RULE: &str = "----------------------------------------------------------------";

pub fn format_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let n = n as f64;
    if n < KB {
        format!("{n:.0}B")
    } else if n < KB * KB {
        format!("{:.1}KB", n / KB)
    } else if n < KB * KB * KB {
        format!("{:.1}MB", n / (KB * KB))
    } else {
        format!("{:.2}GB", n / (KB * KB * KB))
    }
}

/// 5x5 block glyph for each letter used in the "CURFEW" wordmark.
fn glyph(c: char) -> [&'static str; 5] {
    match c {
        'C' => [" ████", "█    ", "█    ", "█    ", " ████"],
        'U' => ["█   █", "█   █", "█   █", "█   █", " ███ "],
        'R' => ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
        'F' => ["█████", "█    ", "████ ", "█    ", "█    "],
        'E' => ["█████", "█    ", "████ ", "█    ", "█    "],
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

/// What the dashboard says about one device.
enum Status {
    Exempt,
    Blocked,
    Throttled(String),
}

/// One row of the device table.
struct Row {
    ip: String,
    label: String,
    status: Status,
    bytes: Option<u64>,
}

fn device_rows(state: &Arc<Mutex<State>>, iface: &str, snapshot: &tc::Snapshot) -> Vec<Row> {
    let (throttled, exempt) = {
        let st = lock_state(state);
        (st.devices.clone(), st.exempt_online.clone())
    };

    let mut rows: Vec<Row> = throttled
        .iter()
        .map(|ip| {
            let st = lock_state(state);
            let status = if st.is_blocked(ip) {
                Status::Blocked
            } else {
                Status::Throttled(rate::friendly(&st.effective_rate(ip)).to_string())
            };
            drop(st);
            Row {
                ip: ip.clone(),
                label: display_name(state, iface, ip),
                status,
                bytes: snapshot.for_device(ip),
            }
        })
        .collect();

    rows.extend(exempt.iter().map(|ip| Row {
        ip: ip.clone(),
        label: display_name(state, iface, ip),
        status: Status::Exempt,
        bytes: None,
    }));

    rows
}

fn draw_dashboard(state: &Arc<Mutex<State>>, iface: &str, my_ip: &str) {
    print_logo();

    let (scans, schedule, pause_until, bypass) = {
        let st = lock_state(state);
        (
            st.scan_count,
            st.schedule.clone(),
            st.pause_until,
            st.ipv6_bypass.clone(),
        )
    };

    let break_mins = pause_until.and_then(|u| {
        let now = std::time::Instant::now();
        (now < u).then(|| (u - now).as_secs() / 60 + 1)
    });
    let pulse = if scans.is_multiple_of(2) { "●" } else { "○" };

    println!("{BOLD}{CYAN}Curfew is on{RESET}{DIM}  {GREEN}{pulse}{RESET}{DIM} watching your network (checked {scans} times){RESET}");
    if let Some(mins) = break_mins {
        println!("{GREEN}Break on: everyone has full speed for about {mins} more minute(s).{RESET}");
    }

    match &schedule {
        None => {
            println!("{DIM}No bedtime hours set — internet stays slowed all the time.{RESET}");
        }
        Some(schedule) => {
            let on_now = schedule::is_active(&Some(schedule.clone()));
            let when = schedule
                .windows
                .iter()
                .map(|w| w.describe())
                .collect::<Vec<_>>()
                .join("  ·  ");
            let verdict = if on_now {
                format!("{RED}on now, internet is slowed{RESET}")
            } else {
                format!("{GREEN}off now, everyone has full speed{RESET}")
            };
            println!("{DIM}Bedtime hours:{RESET} {when}");
            println!("{DIM}                {verdict}");
        }
    }
    println!("{RULE}");

    println!("{BOLD}{GREEN}{my_ip:<16}{RESET} {:<24}{GREEN}full speed{RESET}", "you");

    let snapshot = tc::snapshot(iface);
    let rows = device_rows(state, iface, &snapshot);
    if rows.is_empty() {
        println!("{DIM}No other devices found yet — still looking...{RESET}");
    } else {
        for row in &rows {
            let usage = match (&snapshot.available, row.bytes) {
                (true, Some(bytes)) => format!("{DIM}{:>8}{RESET}", format_bytes(bytes)),
                _ => String::new(),
            };
            match &row.status {
                Status::Exempt => println!(
                    "{GREEN}{:<16}{RESET} {:<24}{GREEN}full speed (you allowed this one){RESET}",
                    row.ip, row.label
                ),
                Status::Blocked => println!(
                    "{RED}{:<16}{RESET} {:<24}{RED}no internet{RESET} {usage}",
                    row.ip, row.label
                ),
                Status::Throttled(slowed) => println!(
                    "{RED}{:<16}{RESET} {:<24}{YELLOW}{slowed}{RESET} {usage}",
                    row.ip, row.label
                ),
            }
        }
    }

    if snapshot.available {
        println!(
            "{DIM}Data slowed so far: {} · Data at full speed: {}{RESET}",
            format_bytes(snapshot.throttled_bytes),
            format_bytes(snapshot.fast_bytes)
        );
    } else {
        println!("{DIM}(This system doesn't report per-lane traffic totals.){RESET}");
    }

    if !bypass.is_empty() {
        println!("{RULE}");
        println!(
            "{YELLOW}Heads up: {} device(s) can still reach the internet at full speed over IPv6.{RESET}",
            bypass.len()
        );
        println!("{DIM}Curfew only slows IPv4. Turn off IPv6 on your router to close this.{RESET}");
    }
    println!("{RULE}");
}

fn draw_menu() {
    // Grouped by what the user is trying to do, not by implementation. The
    // numbers are kept stable — people who use this daily have them memorised.
    println!("{DIM}Devices{RESET}");
    println!("{BOLD}1{RESET}) Give a device full speed");
    println!("{BOLD}2{RESET}) Take full speed away from a device");
    println!("{BOLD}8{RESET}) Change one device's speed, or block it");
    println!("{BOLD}4{RESET}) Give a device a nickname");
    println!();
    println!("{DIM}The whole network{RESET}");
    println!("{BOLD}6{RESET}) Change how slow the internet is");
    println!("{BOLD}7{RESET}) Give everyone full speed for a while");
    println!("{BOLD}3{RESET}) Set bedtime hours (when to slow the internet)");
    println!();
    println!("{DIM}Looking back{RESET}");
    println!("{BOLD}5{RESET}) See what's been happening");
    println!("{BOLD}9{RESET}) See every device you've had (and when)");
    println!("{BOLD}10{RESET}) See who's been using Curfew");
    println!();
    println!("{BOLD}0{RESET}) Stop Curfew (put everyone back to normal)");
    println!("{RULE}");
}

fn print_logs(state: &Arc<Mutex<State>>) {
    clear_screen();
    println!("{BOLD}{CYAN}What's been happening{RESET}");
    println!("{RULE}");
    let logs = lock_state(state).logs.clone();
    if logs.is_empty() {
        println!("{DIM}Nothing yet.{RESET}");
    } else {
        for line in logs.iter().rev().take(40).rev() {
            println!("{DIM}{line}{RESET}");
        }
    }

    // The sites devices have asked for, which is the closest thing to "what
    // are they doing" that survives HTTPS.
    println!("{RULE}");
    if let Some(reason) = dnswatch::unavailability_reason() {
        println!("{DIM}{reason}{RESET}");
    } else if !dnswatch::is_running() {
        println!("{DIM}Not watching which sites are being asked for.{RESET}");
    } else {
        let busiest = lock_state(state).devices.clone();
        let mut any = false;
        for ip in &busiest {
            let (domain_count, sites) = dnswatch::with_log(|log| {
                (
                    log.total_for(ip),
                    log.domains_for(ip).into_iter().take(6).collect::<Vec<_>>(),
                )
            });
            if sites.is_empty() {
                continue;
            }
            any = true;
            println!(
                "{BOLD}{ip}{RESET} {DIM}asked for {domain_count} name(s), including:{RESET}"
            );
            for site in sites {
                println!("    {CYAN}{site}{RESET}");
            }
        }
        let top = dnswatch::with_log(|log| log.top_domains(5));
        if !top.is_empty() {
            println!();
            println!("{DIM}Most asked-for overall:{RESET}");
            for (domain, count) in top {
                println!("    {DIM}{domain} ({count}){RESET}");
            }
        }
        if !any {
            let watched = dnswatch::with_log(|log| log.tracked_devices());
            if watched > 0 {
                println!("{DIM}Watching {watched} device(s); no lookups seen yet.{RESET}");
            } else {
                println!("{DIM}No lookups seen yet. Only devices being slowed are visible.{RESET}");
            }
        }
        println!("{DIM}(Sites, not page contents — HTTPS is encrypted. Devices using{RESET}");
        println!("{DIM}DNS-over-HTTPS won't show up here.){RESET}");
    }

    println!("{RULE}");
    prompt(&format!("{CYAN}Press Enter to go back...{RESET}"));
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Everything we've ever seen on this network, including devices that are
/// offline right now — which is what answers "when was that connected?".
fn history_menu(inventory: &Arc<Mutex<Inventory>>) {
    loop {
        clear_screen();
        println!("{BOLD}{CYAN}Every device you've had{RESET}");
        println!("{RULE}");

        let now = now_epoch();
        let rows: Vec<(String, String, String, bool, bool)> = {
            let inventory = inventory.lock().unwrap_or_else(|p| p.into_inner());
            inventory
                .recent()
                .iter()
                .map(|record| {
                    (
                        record.mac.clone(),
                        record.label(),
                        record.last_seen_phrase(now),
                        record.online,
                        record.has_randomised_mac(),
                    )
                })
                .collect()
        };

        if rows.is_empty() {
            println!("{DIM}No devices seen yet. Give it a scan or two.{RESET}");
            println!("{RULE}");
            prompt(&format!("{CYAN}Press Enter to go back...{RESET}"));
            return;
        }

        println!(
            "{DIM}{} device(s) remembered:{RESET}",
            inventory.lock().map(|inv| inv.len()).unwrap_or(0)
        );
        println!();

        for (index, (mac, label, last_seen, online, randomised)) in rows.iter().enumerate() {
            let marker = if *online { format!("{GREEN}●{RESET}") } else { format!("{DIM}○{RESET}") };
            let warning = if *randomised {
                format!(" {YELLOW}[changing address]{RESET}")
            } else {
                String::new()
            };
            println!(
                "{CYAN}{:>2}){RESET} {marker} {BOLD}{:<26}{RESET} {DIM}{:<20}{RESET}{warning}",
                index + 1,
                truncate(label, 26),
                last_seen
            );
            println!("        {DIM}{mac}{RESET}");
        }

        println!("{RULE}");
        println!("{DIM}The filled dot means online right now.{RESET}");
        println!("{DIM}Devices with a changing address may not keep their settings.{RESET}");
        let choice = prompt(&format!(
            "{CYAN}Type a number to forget that device, or Enter to go back: {RESET}"
        ));
        if choice.is_empty() {
            return;
        }
        match choice.parse::<usize>() {
            Ok(n) if n >= 1 && n <= rows.len() => {
                let mac = rows[n - 1].0.clone();
                {
                    let mut inventory = inventory.lock().unwrap_or_else(|p| p.into_inner());
                    inventory.forget(&mac);
                    inventory.save();
                }
                println!("{YELLOW}Forgot {mac}. It'll be added again next time it's on.{RESET}\n");
                prompt("Press Enter to continue...");
            }
            _ => return,
        }
    }
}

/// Shortens a label for a fixed-width column.
fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// "3 min ago" — the shared formatter, used for session ages.
use crate::inventory::humanise_age as short_age;

/// Who has been using Curfew, and from where.
///
/// This is the answer to "has anyone else been in here?" — every sign-in is
/// listed with the address it came from, wrong passwords are called out, and
/// any session still open can be ended from here.
fn security_menu(iface: &str, ctx: &MenuContext) {
    let panel_port = ctx.panel_port;
    clear_screen();
    println!("{BOLD}{CYAN}Who's been using Curfew{RESET}");
    println!("{RULE}");

    match accesslog::with_log(|log| log.last_sign_in().cloned()) {
        Some(entry) => println!(
            "Last sign-in:  {BOLD}{}{RESET} from {BOLD}{}{RESET}",
            entry.when(),
            entry.actor
        ),
        None => println!("{DIM}Last sign-in:  nobody has used the web panel yet.{RESET}"),
    }

    // Sessions still open, so the owner can see and end them.
    let mut session_ids: Vec<String> = Vec::new();
    match ctx.web {
        Some(context) => {
            let sessions = {
                let mut guard = context
                    .sessions
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.list(std::time::Instant::now())
            };
            println!(
                "Panel:         {BOLD}{}{RESET} session(s) signed in",
                sessions.len()
            );
            println!();
            println!("{BOLD}Signed in right now{RESET}");
            if sessions.is_empty() {
                println!("{DIM}  Nobody.{RESET}");
            }
            for (index, info) in sessions.iter().enumerate() {
                println!(
                    "  {CYAN}{}){RESET} {} {DIM}from {} · signed in {}, last used {}{RESET}",
                    index + 1,
                    info.id,
                    info.ip,
                    short_age(info.age_secs),
                    short_age(info.idle_secs)
                );
                session_ids.push(info.id.clone());
            }
        }
        None => println!("{DIM}Panel:         not running (start it with --web){RESET}"),
    }

    let alerts: Vec<accesslog::Entry> =
        accesslog::with_log(|log| log.alerts(6).into_iter().cloned().collect());
    if !alerts.is_empty() {
        println!();
        println!("{BOLD}{YELLOW}Worth a look{RESET}");
        for entry in &alerts {
            println!("  {YELLOW}!{RESET} {}", entry.describe());
        }
    }

    // Someone else intercepting traffic on this network. This is the active
    // version of the question: not "is a panel listening" but "is another
    // tool throttling devices right now".
    println!();
    println!("{BOLD}Someone else spoofing the network{RESET}");
    if arpwatch::is_running() {
        let findings: Vec<String> = arpwatch::with_watcher(|watcher| {
            watcher.findings(5).iter().map(|f| f.describe()).collect()
        })
        .unwrap_or_default();
        if findings.is_empty() {
            println!("{DIM}  Nothing suspicious seen.{RESET}");
        } else {
            for text in &findings {
                println!("  {RED}!{RESET} {text}");
            }
        }
        let contested = arpwatch::with_watcher(|watcher| watcher.contested().len()).unwrap_or(0);
        if contested > 0 {
            println!(
                "  {YELLOW}{contested} address(es) are being claimed twice — those devices \
                 are being interfered with.{RESET}"
            );
        }
    } else if let Some(reason) = arpwatch::unavailability_reason() {
        println!("{DIM}{reason}{RESET}");
    } else {
        println!("{DIM}Not watching.{RESET}");
    }

    let sources = accesslog::with_log(|log| log.sign_in_sources());
    println!();
    println!("{BOLD}Who has signed in{RESET}");
    if sources.is_empty() {
        println!("{DIM}  Nobody yet.{RESET}");
    }
    for (actor, count, at) in &sources {
        let failures = accesslog::with_log(|log| log.failures_from(actor));
        let note = if failures > 0 {
            format!(" {RED}({failures} wrong password(s)){RESET}")
        } else {
            String::new()
        };
        println!(
            "  {BOLD}{actor}{RESET} {DIM}— {count} sign-in(s), last {}{RESET}{note}",
            accesslog::when_text(*at)
        );
    }

    println!("{RULE}");
    println!("{BOLD}1{RESET}) Sign out a session");
    println!("{BOLD}2{RESET}) Check the network for another Curfew panel");
    println!("{BOLD}3{RESET}) See everything recorded");
    println!("{BOLD}4{RESET}) See who is claiming which address");
    println!("{BOLD}5{RESET}) Clear these findings once I've read them");
    if defense::is_enabled() {
        println!("{BOLD}6{RESET}) Turn the defense OFF (unpin everything)");
    } else {
        println!("{BOLD}6{RESET}) Turn the defense ON (pin real addresses)");
    }
    let choice = prompt(&format!("{CYAN}Choose, or press Enter to go back: {RESET}"));

    if choice.trim() == "6" {
        toggle_defense(iface);
        return;
    }

    match choice.trim() {
        "1" => {
            if session_ids.is_empty() {
                println!("{DIM}There are no sessions to sign out.{RESET}\n");
                prompt("Press Enter to go back...");
                return;
            }
            let pick = prompt(&format!("{CYAN}Which number? {RESET}"));
            if let Ok(n) = pick.trim().parse::<usize>() {
                if n >= 1 && n <= session_ids.len() {
                    let id = session_ids[n - 1].clone();
                    if let Some(context) = ctx.web {
                        let revoked = {
                            let mut guard = context
                                .sessions
                                .lock()
                                .unwrap_or_else(|p| p.into_inner());
                            guard.revoke_prefix(&id)
                        };
                        if revoked > 0 {
                            accesslog::record(
                                accesslog::Kind::SessionRevoked,
                                accesslog::ACTOR_TERMINAL,
                                &format!("signed out session {id}"),
                            );
                            println!("{GREEN}Done. That session has been signed out.{RESET}\n");
                        } else {
                            println!("{YELLOW}That session had already ended.{RESET}\n");
                        }
                    }
                }
            }
            prompt("Press Enter to go back...");
        }
        "2" => {
            clear_screen();
            println!("{BOLD}{CYAN}Looking for another Curfew panel{RESET}");
            println!("{RULE}");
            println!("{DIM}Checking port {panel_port} on your network...{RESET}");
            let subnet = network::get_subnet(iface);
            let my_ip = network::get_own_ip(iface);
            match watchdog::scan_for_panels(&subnet, &my_ip, panel_port) {
                Ok(hosts) if hosts.is_empty() => {
                    println!("{GREEN}Nothing found — only this machine is running Curfew.{RESET}");
                }
                Ok(hosts) => {
                    watchdog::report_other_panels(&hosts, panel_port);
                    for host in &hosts {
                        accesslog::record(
                            accesslog::Kind::OtherPanel,
                            accesslog::ACTOR_TERMINAL,
                            &format!("panel at {host}:{panel_port}"),
                        );
                    }
                }
                Err(e) => println!("{RED}Couldn't check: {e}{RESET}"),
            }
            println!("{RULE}");
            prompt("Press Enter to go back...");
        }
        "3" => {
            clear_screen();
            println!("{BOLD}{CYAN}Everything recorded{RESET}");
            println!("{RULE}");
            let entries: Vec<accesslog::Entry> =
                accesslog::with_log(|log| log.all_recent().into_iter().cloned().collect());
            let total = accesslog::with_log(|log| log.len());
            println!("{DIM}{total} event(s), newest first.{RESET}");
            println!();
            if entries.is_empty() {
                println!("{DIM}Nothing yet.{RESET}");
            }
            for entry in &entries {
                let colour = if entry.kind.is_alert() { RED } else { DIM };
                println!("{colour}{}{RESET}", entry.describe());
            }
            println!("{RULE}");
            prompt("Press Enter to go back...");
        }
        "4" => {
            clear_screen();
            println!("{BOLD}{CYAN}Who is claiming which address{RESET}");
            println!("{RULE}");
            println!("{DIM}An address claimed by two machines is one being interfered with.{RESET}");
            println!();
            let rows: Vec<(String, Vec<String>)> = arpwatch::with_watcher(|watcher| {
                watcher
                    .bindings()
                    .iter()
                    .map(|binding| (binding.ip.clone(), binding.macs.clone()))
                    .collect()
            })
            .unwrap_or_default();
            if rows.is_empty() {
                println!("{DIM}Nothing seen yet.{RESET}");
            }
            for (ip, macs) in &rows {
                let colour = if macs.len() > 1 { RED } else { DIM };
                println!("{colour}{ip:<16} {}{RESET}", macs.join("  and  "));
            }
            println!("{RULE}");
            prompt("Press Enter to go back...");
        }
        "5" => {
            // Without this the list only ever grows, and a warning nobody can
            // dismiss is one people stop reading. Clearing doesn't blind the
            // watcher: if the interference is still going on, the next
            // announcement of that address raises it again.
            let before = arpwatch::with_watcher(|watcher| watcher.findings(usize::MAX).len())
                .unwrap_or(0);
            arpwatch::with_watcher_mut(|watcher| watcher.clear_findings());
            println!("{GREEN}Cleared {before} finding(s). New ones will be reported.{RESET}\n");
            prompt("Press Enter to go back...");
        }
        _ => {}
    }
}

/// Turns the defense on or off, with a plain-words explanation either way.
fn toggle_defense(iface: &str) {
    clear_screen();
    println!("{BOLD}{CYAN}Defense against a network spoofer{RESET}");
    println!("{RULE}");
    if defense::is_enabled() {
        println!("{DIM}Defense is currently ON. Curfew pins the real hardware address{RESET}");
        println!("{DIM}of the router and of any device being interfered with, so a{RESET}");
        println!("{DIM}spoofer's replies are ignored. It re-asserts them every scan.{RESET}");
        println!();
        let pins = defense::list_pins();
        if pins.is_empty() {
            println!("{DIM}Nothing is pinned yet — no spoofer has been detected.{RESET}");
        }
        for pin in &pins {
            println!(
                "  {GREEN}●{RESET} {} {} {DIM}({}){RESET}",
                pin.ip,
                pin.mac,
                pin.reason.label()
            );
        }
        println!();
        if prompt(&format!("{CYAN}Turn it OFF? (y/N): {RESET}"))
            .trim()
            .eq_ignore_ascii_case("y")
        {
            let removed = defense::disable();
            accesslog::record(
                accesslog::Kind::Defense,
                accesslog::ACTOR_TERMINAL,
                &format!("defense turned off ({} pin(s) removed)", removed.len()),
            );
            println!("{YELLOW}Defense is off. {} pin(s) removed.{RESET}", removed.len());
        } else {
            println!("{DIM}Left on.{RESET}");
        }
    } else {
        println!("{DIM}Defense is currently OFF. If someone is throttling devices{RESET}");
        println!("{DIM}on this network, Curfew will report it but not intervene.{RESET}");
        println!();
        let answer = prompt(&format!("{CYAN}Turn it ON? (Y/n): {RESET}"));
        if answer.trim().is_empty() || answer.trim().eq_ignore_ascii_case("y") {
            let pins = defense::enable(iface, Vec::new());
            accesslog::record(
                accesslog::Kind::Defense,
                accesslog::ACTOR_TERMINAL,
                &format!("defense turned on ({} pin(s))", pins.len()),
            );
            println!("{GREEN}Defense is on. New pins will be applied on the next scan.{RESET}");
        } else {
            println!("{DIM}Left off.{RESET}");
        }
    }
    println!("{RULE}");
    prompt("Press Enter to go back...");
}

/// Everything the menu needs besides the live device state. Bundled so the
/// parameter list stays readable as features are added.
pub struct MenuContext<'a> {
    pub inventory: &'a Arc<Mutex<Inventory>>,
    /// Present only when the web panel is running.
    pub web: Option<&'a Arc<crate::web::WebContext>>,
    /// The port a panel would be listening on, for the network check.
    pub panel_port: u16,
}

/// Asks the user to pick one of `ips` by number. `None` means "go back".
fn choose_device(ips: &[String], title: &str) -> Option<usize> {
    if ips.is_empty() {
        return None;
    }
    println!("\n{BOLD}{title}{RESET}");
    for (i, ip) in ips.iter().enumerate() {
        println!("  {CYAN}{}){RESET} {ip}", i + 1);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Type its number and press Enter (or just Enter to go back): {RESET}"
    ));
    if choice.is_empty() {
        return None;
    }
    match choice.parse::<usize>() {
        Ok(n) if n >= 1 && n <= ips.len() => Some(n - 1),
        _ => {
            println!("{RED}That wasn't one of the numbers above.{RESET}");
            None
        }
    }
}

fn back_to_menu() {
    prompt("Press Enter to go back...");
}

/// Permanently exempts `ip`'s MAC, so it always gets full speed from now on,
/// including after restarts.
///
/// The work itself lives in [`crate::devices::grant_full_speed`], shared with
/// the web panel so both record to the audit log the same way. This wrapper
/// only adds the terminal confirmation.
fn grant_full_speed(iface: &str, ip: &str, state: &Arc<Mutex<State>>) {
    let mac = do_grant(iface, ip, state);
    println!("{GREEN}Done. {ip} ({mac}) will always have full speed from now on.{RESET}\n");
}

/// Removes a previously-exempted MAC; it'll be throttled again next time it's
/// seen on the network (within one scan interval).
fn revoke_full_speed(mac: &str, state: &Arc<Mutex<State>>) {
    do_revoke(mac, state);
    println!("{YELLOW}Done. {mac} will be slowed down again shortly.{RESET}\n");
}

fn allow_menu(iface: &str, state: &Arc<Mutex<State>>) {
    let devices = lock_state(state).devices.clone();
    if devices.is_empty() {
        println!("\n{DIM}Nobody is being slowed down right now.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    if let Some(index) = choose_device(&devices, "Which device should get full speed?") {
        let ip = devices[index].clone();
        grant_full_speed(iface, &ip, state);
    }
    back_to_menu();
}

fn revoke_menu(state: &Arc<Mutex<State>>) {
    let allowed = lock_state(state).allowed_macs.clone();
    if allowed.is_empty() {
        println!("\n{DIM}Nobody is on the full-speed list right now.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    if let Some(index) = choose_device(&allowed, "Which device should go back to being slowed down?")
    {
        let mac = allowed[index].clone();
        revoke_full_speed(&mac, state);
    }
    back_to_menu();
}

/// Changes one device's speed, blocks it, or puts it back on the household
/// default — without touching anyone else.
fn device_menu(iface: &str, state: &Arc<Mutex<State>>) {
    let devices = lock_state(state).devices.clone();
    if devices.is_empty() {
        println!("\n{DIM}No devices are being managed yet — still looking.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }

    let Some(index) = choose_device(&devices, "Which device do you want to change?") else {
        return;
    };
    let ip = devices[index].clone();
    let mac = get_mac(state, iface, &ip);
    let current = {
        let st = lock_state(state);
        match st.modes.get(&mac) {
            Some(DeviceMode::Block) => "blocked".to_string(),
            Some(DeviceMode::Rate(r)) => format!("{} ({r})", rate::friendly(r)),
            None => format!("the household setting ({})", rate::friendly(&st.rate)),
        }
    };
    let label = display_name(state, iface, &ip);

    println!("\n{BOLD}{label}{RESET} {DIM}({ip}){RESET}");
    println!("{DIM}Right now this device is: {current}{RESET}");
    println!("\n{BOLD}What should happen to just this device?{RESET}");
    for (i, choice) in rate::CHOICES.iter().enumerate() {
        println!("  {CYAN}{}){RESET} {}", i + 1, choice.menu);
    }
    let block_number = rate::CHOICES.len() + 1;
    let default_number = rate::CHOICES.len() + 2;
    println!("  {CYAN}{block_number}){RESET} {RED}No internet at all{RESET}");
    println!("  {CYAN}{default_number}){RESET} Same as everyone else");

    let choice = prompt(&format!(
        "\n{CYAN}Type a number and press Enter (or just Enter to go back): {RESET}"
    ));
    let parsed = match choice.trim().parse::<usize>() {
        Ok(n) => n,
        Err(_) => return,
    };

    let new_mode = if parsed >= 1 && parsed <= rate::CHOICES.len() {
        Some(DeviceMode::Rate(rate::CHOICES[parsed - 1].key.to_string()))
    } else if parsed == block_number {
        Some(DeviceMode::Block)
    } else if parsed == default_number {
        // Back to the household setting: no per-device override at all.
        None
    } else {
        println!("{RED}That wasn't one of the numbers above.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    };

    // The shared helper updates the mode, starts throttling the device if it
    // isn't managed yet, re-applies shaping, and records the change — the
    // same path the web panel takes.
    set_device_mode(iface, &ip, &mac, new_mode, state);

    let summary = {
        let st = lock_state(state);
        match st.modes.get(&mac) {
            Some(DeviceMode::Block) => "no internet".to_string(),
            Some(DeviceMode::Rate(r)) => rate::friendly(r).to_string(),
            None => format!("same as everyone else ({})", rate::friendly(&st.rate)),
        }
    };
    println!("{GREEN}Done. {label} is now: {summary}.{RESET}\n");
    prompt("Press Enter to go back...");
}

/// Sets, changes, or clears the daily curfew windows.
fn schedule_menu(state: &Arc<Mutex<State>>) {
    println!();
    let existing = lock_state(state).schedule.clone();
    match &existing {
        Some(schedule) if !schedule.windows.is_empty() => {
            println!("{BOLD}Right now, bedtime hours are:{RESET}");
            for window in &schedule.windows {
                println!("  {CYAN}{}{RESET}", window.describe());
            }
        }
        _ => println!("{DIM}No bedtime hours set — the internet is slowed all the time.{RESET}"),
    }

    println!();
    println!("  {CYAN}1){RESET} Add another window {DIM}(e.g. weekends different from school nights){RESET}");
    println!("  {CYAN}2){RESET} Replace all windows");
    println!("  {CYAN}3){RESET} Turn bedtime hours off (always slowed)");
    let choice = prompt(&format!(
        "\n{CYAN}Type a number and press Enter (or just Enter to go back): {RESET}"
    ));

    let mut windows = match choice.trim() {
        "1" => existing.map(|s| s.windows).unwrap_or_default(),
        "2" => Vec::new(),
        "3" => {
            {
                let mut st = lock_state(state);
                st.schedule = None;
            }
            schedule::clear();
            println!("{GREEN}Done. The internet will stay slowed all the time now.{RESET}\n");
            prompt("Press Enter to go back...");
            return;
        }
        _ => return,
    };

    let Some(window) = ask_window() else {
        return;
    };
    windows.push(window);

    let schedule = Schedule { windows };
    {
        let mut st = lock_state(state);
        st.schedule = Some(schedule.clone());
    }
    schedule::save(&schedule);

    println!("{GREEN}Done. Bedtime hours are now:{RESET}");
    for window in &schedule.windows {
        println!("  {CYAN}{}{RESET}", window.describe());
    }
    println!();
    prompt("Press Enter to go back...");
}

/// Walks the user through one window: which days, then the two times.
fn ask_window() -> Option<Window> {
    println!();
    println!("{DIM}Days it applies to — like \"everyday\", \"weekends\", \"mon-fri\",{RESET}");
    println!("{DIM}or a list such as \"sat,sun\".{RESET}");
    let days_input = prompt(&format!("{CYAN}Which days? {RESET}"));
    let days = if days_input.trim().is_empty() {
        DaySet::EVERY
    } else {
        match DaySet::parse(&days_input) {
            Some(days) => days,
            None => {
                println!("{RED}I didn't understand those days. Nothing changed.{RESET}\n");
                prompt("Press Enter to go back...");
                return None;
            }
        }
    };

    println!("{DIM}Use 24-hour time, like 20:00 for 8pm or 07:00 for 7am.{RESET}");
    let start = prompt(&format!("{CYAN}Start slowing the internet at: {RESET}"));
    let end = prompt(&format!("{CYAN}Go back to full speed at: {RESET}"));

    if !schedule::valid(&start) || !schedule::valid(&end) {
        println!("{RED}That didn't look like a time. Use 24-hour time like 20:00. Nothing changed.{RESET}\n");
        prompt("Press Enter to go back...");
        return None;
    }

    Some(Window::new(days, &start, &end))
}

/// Gives a device a friendly name (e.g. "Timmy's iPad") shown everywhere
/// instead of its raw MAC address.
fn name_menu(iface: &str, state: &Arc<Mutex<State>>) {
    let devices = lock_state(state).devices.clone();
    if devices.is_empty() {
        println!("\n{DIM}No devices to nickname yet.{RESET}\n");
        prompt("Press Enter to go back...");
        return;
    }
    let Some(index) = choose_device(&devices, "Which device do you want to nickname?") else {
        return;
    };
    let ip = devices[index].clone();
    let name = prompt("Type a nickname (like Tim's iPad) and press Enter: ");
    if name.is_empty() {
        return;
    }
    let mac = get_mac(state, iface, &ip);
    {
        let mut st = lock_state(state);
        st.names.insert(mac, name.clone());
        save_names(&st.names);
    }
    println!("{GREEN}Done. That device is now called \"{name}\".{RESET}\n");
    prompt("Press Enter to go back...");
}

/// Changes how slow everyone else's internet is, right now, without
/// restarting — and remembers it for next time.
fn speed_menu(iface: &str, state: &Arc<Mutex<State>>) {
    let current = lock_state(state).rate.clone();
    println!("\n{BOLD}How slow should everyone else's internet be?{RESET}");
    println!("{DIM}Right now it's set to: {} ({current}){RESET}", rate::friendly(&current));
    for (i, choice) in rate::CHOICES.iter().enumerate() {
        println!("  {CYAN}{}){RESET} {}", i + 1, choice.menu);
    }
    let choice = prompt(&format!(
        "\n{CYAN}Type a number and press Enter (or just Enter to go back): {RESET}"
    ));

    let selected = match choice.trim().parse::<usize>() {
        Ok(n) if n >= 1 && n <= rate::CHOICES.len() => rate::CHOICES[n - 1].key,
        _ => return,
    };

    // Shared with the web panel, which also records the change.
    set_household_rate(iface, selected, state);
    println!("{GREEN}Done. The new speed is in effect now.{RESET}\n");
    prompt("Press Enter to go back...");
}

/// Grants everyone full speed for a chosen number of minutes, after which the
/// slowing comes back automatically (handled by the monitor thread).
fn break_menu(state: &Arc<Mutex<State>>) {
    let on_break = lock_state(state)
        .pause_until
        .map(|u| std::time::Instant::now() < u)
        .unwrap_or(false);

    println!("\n{BOLD}Give everyone full speed for a while?{RESET}");
    println!("  {CYAN}1){RESET} 15 minutes");
    println!("  {CYAN}2){RESET} 30 minutes");
    println!("  {CYAN}3){RESET} 1 hour");
    if on_break {
        println!("  {CYAN}4){RESET} End the break now (go back to slow)");
    }
    let choice = prompt(&format!(
        "\n{CYAN}Type a number and press Enter (or just Enter to go back): {RESET}"
    ));
    let mins: u64 = match choice.trim() {
        "1" => 15,
        "2" => 30,
        "3" => 60,
        "4" if on_break => {
            // Shared with the web panel, which also records the change.
            set_pause(state, None);
            println!("{YELLOW}Break ended. Everyone will be slowed again shortly.{RESET}\n");
            prompt("Press Enter to go back...");
            return;
        }
        _ => return,
    };
    set_pause(state, Some(mins));
    println!("{GREEN}Done. Everyone has full speed for {mins} minutes. It goes back to slow on its own.{RESET}\n");
    prompt("Press Enter to go back...");
}

/// Redraws the dashboard every [`REFRESH_INTERVAL`] until the user actually
/// types something, so it never looks stale.
fn wait_for_command(iface: &str, my_ip: &str, state: &Arc<Mutex<State>>) -> String {
    loop {
        clear_screen();
        draw_dashboard(state, iface, my_ip);
        draw_menu();
        print_flush(&format!("{CYAN}Choose an option: {RESET}"));
        if let Some(line) = stdin::read_line_timeout(REFRESH_INTERVAL) {
            return line;
        }
    }
}

pub fn run_menu(iface: &str, my_ip: &str, state: &Arc<Mutex<State>>, ctx: &MenuContext) {
    loop {
        match wait_for_command(iface, my_ip, state).as_str() {
            "1" => allow_menu(iface, state),
            "2" => revoke_menu(state),
            "3" => schedule_menu(state),
            "4" => name_menu(iface, state),
            "5" => print_logs(state),
            "6" => speed_menu(iface, state),
            "7" => break_menu(state),
            "8" => device_menu(iface, state),
            "9" => history_menu(ctx.inventory),
            "10" => security_menu(iface, ctx),
            "0" => cleanup(state),
            "" => {}
            _ => {
                println!("{RED}Please type one of the numbers shown in the menu (0 to 10).{RESET}");
                prompt("Press Enter to go back...");
            }
        }
    }
}

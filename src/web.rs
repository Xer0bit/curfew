//! The web control panel: a small HTTP server that lets the owner change
//! Curfew's settings from a browser, including from outside the house.
//!
//! # Security model
//!
//! This process runs as **root** and can cut a household's internet off, so
//! the threat model is taken seriously:
//!
//! - **Every action requires a session.** There is no unauthenticated read or
//!   write path; the only thing served without a session is the login page.
//! - **Passwords are verified with PBKDF2**, never stored or logged in clear.
//! - **Sessions** are 32 random bytes, held in an `HttpOnly`, `SameSite=Strict`
//!   cookie, and expire on both an idle and an absolute timeout.
//! - **CSRF**: state-changing requests must carry a per-session token, on top
//!   of `SameSite=Strict`.
//! - **Login is rate-limited per IP** with exponential backoff, and password
//!   hashing is serialised so a burst of attempts can't saturate the CPU
//!   (each verification costs over a second by design).
//! - **Nothing is exposed to the internet by default.** The intended way to
//!   reach it from elsewhere is a VPN or SSH tunnel. If you do put it behind a
//!   reverse proxy, `--trust-proxy` makes it honour `X-Forwarded-For` for rate
//!   limiting and mark cookies `Secure`.
//!
//! # What it deliberately does not do
//!
//! No TLS. Doing it properly means certificate management, which belongs in a
//! reverse proxy or a tunnel that already solves it. Serving plain HTTP over
//! the open internet would be worse than not offering it.
//!
//! # Layout
//!
//! Everything that can be tested is a free function with no socket involved:
//! request parsing, form decoding, escaping, sessions, and rate limiting. The
//! socket loop is a thin shell on top.

use crate::accesslog::{self, Kind};
use crate::colors::{BOLD, CYAN, DIM, RESET, YELLOW};
use crate::devices;
use crate::inventory::Inventory;
use crate::rate;
use crate::schedule;
use crate::state::{DeviceMode, State};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Longest request line or header we'll accept. Anything larger is a mistake
/// or an attack, not a real browser.
const MAX_LINE_BYTES: usize = 8 * 1024;

/// Largest request body accepted. The only body we expect is a small form.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// How long a connection may sit idle mid-request. Without this, a client
/// that opens a connection and sends nothing ties up a thread indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// A session expires after this long without use.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

/// A session expires this long after it was created, however busy it is, so a
/// stolen cookie can't be used forever.
const SESSION_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);

/// Failed logins from one address before backoff starts.
const FREE_LOGIN_ATTEMPTS: u32 = 3;

/// Longest lockout, so a determined attacker can't lock the owner out
/// permanently by failing repeatedly from a spoofed address.
const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);

/// Cap on remembered failure records, so a scan from many addresses can't grow
/// memory without bound.
const MAX_TRACKED_IPS: usize = 1024;

/// Cap on live sessions. There is one owner, so this many open sessions means
/// something unusual is happening.
const MAX_LIVE_SESSIONS: usize = 256;

/// Port the panel listens on when `--web` is given without an address.
/// Public so the watchdog knows which port to look for elsewhere on the
/// network.
pub const DEFAULT_PORT: u16 = 8787;

/// The port from a `--web` address, falling back to [`DEFAULT_PORT`] if the
/// address doesn't name one.
pub fn port_of(address: &str) -> u16 {
    address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// How many characters of a session token are shown when listing sessions.
/// Long enough to tell two apart, far too short to authenticate with — and
/// only ever shown to an already-signed-in owner.
pub const SESSION_ID_CHARS: usize = 8;

/// Serialises password hashing. Each verification deliberately costs over a
/// second; without this, concurrent attempts would pin every core.
static HASH_LOCK: Mutex<()> = Mutex::new(());

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// Every state change the web UI can perform.
///
/// Parsed from form fields, which arrive from the network — so [`Action::parse`]
/// validates every value and rejects anything unrecognised rather than
/// defaulting to something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Permanent full speed, by IP (the MAC is resolved server-side).
    GrantFullSpeed { ip: String },
    /// Take a device off the full-speed list.
    RevokeFullSpeed { mac: String },
    /// Throttle one device at a specific rate.
    SetDeviceRate { ip: String, rate: String },
    /// Cut one device off entirely.
    BlockDevice { ip: String },
    /// Put a device back on the household setting.
    ClearDevice { ip: String },
    /// Change the household rate for everyone else.
    SetHouseholdRate { rate: String },
    /// Everyone gets full speed for a while.
    Pause { minutes: u64 },
    /// End a break early.
    Resume,
    /// Turn the anti-spoofing defense on.
    DefenseOn,
    /// Turn the anti-spoofing defense off and unpin everything.
    DefenseOff,
    /// Stop Curfew and restore the network.
    Stop,
}

impl Action {
    /// Builds an action from decoded form fields.
    pub fn parse(fields: &HashMap<String, String>) -> Result<Action, String> {
        let field = |name: &str| fields.get(name).map(String::as_str).unwrap_or("").trim();
        let action = field("action");

        // IPs come from the network; require something that looks like one
        // rather than passing arbitrary text to `tc`.
        let require_ip = |name: &str| -> Result<String, String> {
            let value = field(name);
            if is_plausible_ipv4(value) {
                Ok(value.to_string())
            } else {
                Err(format!("{name} is not a valid address"))
            }
        };
        let require_mac = |name: &str| -> Result<String, String> {
            let value = field(name);
            crate::oui::normalize_mac(value)
                .ok_or_else(|| format!("{name} is not a valid MAC address"))
        };
        let require_rate = |name: &str| -> Result<String, String> {
            let value = field(name);
            if rate::is_throttle_rate(value) {
                Ok(value.to_string())
            } else {
                Err(format!("{value:?} is not one of the offered speeds"))
            }
        };

        match action {
            "grant" => Ok(Action::GrantFullSpeed {
                ip: require_ip("ip")?,
            }),
            "revoke" => Ok(Action::RevokeFullSpeed {
                mac: require_mac("mac")?,
            }),
            "device_rate" => Ok(Action::SetDeviceRate {
                ip: require_ip("ip")?,
                rate: require_rate("rate")?,
            }),
            "block" => Ok(Action::BlockDevice {
                ip: require_ip("ip")?,
            }),
            "clear_device" => Ok(Action::ClearDevice {
                ip: require_ip("ip")?,
            }),
            "household_rate" => Ok(Action::SetHouseholdRate {
                rate: require_rate("rate")?,
            }),
            "pause" => {
                let minutes: u64 = field("minutes")
                    .parse()
                    .map_err(|_| "minutes must be a number".to_string())?;
                // Bounded so a typo can't disable the throttle for a week.
                if !(1..=24 * 60).contains(&minutes) {
                    return Err("minutes must be between 1 and 1440".to_string());
                }
                Ok(Action::Pause { minutes })
            }
            "resume" => Ok(Action::Resume),
            "defense_on" => Ok(Action::DefenseOn),
            "defense_off" => Ok(Action::DefenseOff),
            "stop" => Ok(Action::Stop),
            "" => Err("no action given".to_string()),
            other => Err(format!("unknown action {other:?}")),
        }
    }

    /// A short phrase naming what changed, with no "who" context, for the
    /// audit log. The actor is recorded separately.
    pub fn summary(&self) -> String {
        match self {
            Action::GrantFullSpeed { ip } => format!("gave {ip} full speed"),
            Action::RevokeFullSpeed { mac } => format!("took full speed from {mac}"),
            Action::SetDeviceRate { ip, rate } => format!("set {ip} to {rate}"),
            Action::BlockDevice { ip } => format!("blocked {ip}"),
            Action::ClearDevice { ip } => format!("reset {ip} to the household speed"),
            Action::SetHouseholdRate { rate } => format!("household speed set to {rate}"),
            Action::Pause { minutes } => format!("everyone full speed for {minutes}m"),
            Action::Resume => "break ended".to_string(),
            Action::DefenseOn => "defense turned on".to_string(),
            Action::DefenseOff => "defense turned off".to_string(),
            Action::Stop => "stop requested".to_string(),
        }
    }

    /// A short phrase for the in-app activity log, noting where it came from.
    pub fn describe(&self) -> String {
        format!("web: {}", self.summary())
    }
}

/// True if `value` is a syntactically valid IPv4 address.
///
/// Deliberately strict: these values reach `tc` command lines, so nothing but
/// a plain address is allowed through. Rules out hostnames, IPv6, and any
/// attempt to smuggle in extra arguments.
pub fn is_plausible_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.chars().all(|c| c.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

// ---------------------------------------------------------------------------
// Form and text encoding
// ---------------------------------------------------------------------------

/// Decodes `application/x-www-form-urlencoded` data into fields.
///
/// Repeated keys keep the first value; an empty field is still recorded, so
/// "present but blank" stays distinguishable from "absent".
pub fn parse_form(body: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        fields
            .entry(percent_decode(key))
            .or_insert_with(|| percent_decode(value));
    }
    fields
}

/// Percent-decoding with `+` as space, per the form-urlencoded rules.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    // A stray '%' is literal, not an error worth rejecting.
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    // Invalid UTF-8 is replaced rather than dropped, so one bad byte can't
    // silently truncate a value.
    String::from_utf8_lossy(&out).into_owned()
}

/// Escapes text for HTML output.
///
/// Essential rather than cosmetic: device hostnames come from the network, so
/// a device calling itself `<script>...</script>` would otherwise run in the
/// owner's browser.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Session {
    /// Per-session CSRF token, handed to the page and required back on writes.
    pub csrf: String,
    /// Where this session signed in from. Recorded so the owner can see who is
    /// using the panel and end a session that isn't theirs.
    pub ip: String,
    created: Instant,
    last_seen: Instant,
}

impl Session {
    fn is_valid(&self, now: Instant) -> bool {
        now.duration_since(self.created) < SESSION_ABSOLUTE_TIMEOUT
            && now.duration_since(self.last_seen) < SESSION_IDLE_TIMEOUT
    }
}

/// A session as shown in the panel: no token, just enough to recognise it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// A short prefix of the token, used to revoke this specific session.
    pub id: String,
    pub ip: String,
    /// How long ago it signed in.
    pub age_secs: u64,
    /// How long since it was last used.
    pub idle_secs: u64,
}

/// Live sessions, keyed by token. Tokens are never written to the log.
#[derive(Default)]
pub struct Sessions {
    entries: HashMap<String, Session>,
}

impl Sessions {
    /// Starts a session, or `None` if no secure random source is available.
    /// Refusing is the only safe behaviour: a predictable token is worse than
    /// no web UI.
    pub fn start(&mut self, now: Instant, ip: &str) -> Option<(String, Session)> {
        let token = crate::random::hex_token(32)?;
        let csrf = crate::random::hex_token(32)?;
        let session = Session {
            csrf,
            ip: ip.to_string(),
            created: now,
            last_seen: now,
        };
        // Bound growth; there is one owner, so many live sessions means
        // something unusual is happening.
        if self.entries.len() > MAX_LIVE_SESSIONS {
            self.prune(now);
        }
        self.entries.insert(token.clone(), session.clone());
        Some((token, session))
    }

    /// Looks a session up, refreshing its idle timer.
    pub fn touch(&mut self, token: &str, now: Instant) -> Option<Session> {
        let still_valid = self
            .entries
            .get(token)
            .map(|session| session.is_valid(now))
            .unwrap_or(false);
        if !still_valid {
            self.entries.remove(token);
            return None;
        }
        let session = self.entries.get_mut(token)?;
        session.last_seen = now;
        Some(session.clone())
    }

    /// Ends one session.
    pub fn end(&mut self, token: &str) {
        self.entries.remove(token);
    }

    /// Drops expired sessions.
    pub fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, session| session.is_valid(now));
    }

    /// Every live session, most recently used first. Token prefixes only.
    pub fn list(&mut self, now: Instant) -> Vec<SessionInfo> {
        self.prune(now);
        let mut sessions: Vec<SessionInfo> = self
            .entries
            .iter()
            .map(|(token, session)| SessionInfo {
                id: token.chars().take(SESSION_ID_CHARS).collect(),
                ip: session.ip.clone(),
                age_secs: now.duration_since(session.created).as_secs(),
                idle_secs: now.duration_since(session.last_seen).as_secs(),
            })
            .collect();
        sessions.sort_by_key(|info| info.idle_secs);
        sessions
    }

    /// Ends the session whose token starts with `prefix`. Returns how many
    /// were ended.
    ///
    /// A prefix is required to be long enough that it can't plausibly match
    /// more than one token.
    pub fn revoke_prefix(&mut self, prefix: &str) -> usize {
        let prefix = prefix.trim();
        if prefix.len() < SESSION_ID_CHARS {
            return 0;
        }
        let before = self.entries.len();
        self.entries.retain(|token, _| !token.starts_with(prefix));
        before - self.entries.len()
    }

    /// Ends every session except the one holding `keep`.
    pub fn revoke_others(&mut self, keep: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|token, _| token == keep);
        before - self.entries.len()
    }
}

#[derive(Clone, Copy, Debug)]
struct Failures {
    count: u32,
    last: Instant,
}

/// Per-address login throttling.
#[derive(Default)]
pub struct LoginGuard {
    failures: HashMap<IpAddr, Failures>,
}

impl LoginGuard {
    /// How long `ip` must wait before another attempt, or `None` if it may
    /// try now.
    pub fn lockout_remaining(&mut self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let record = self.failures.get(&ip)?;
        if record.count < FREE_LOGIN_ATTEMPTS {
            return None;
        }
        let backoff = self.backoff(record.count);
        let elapsed = now.duration_since(record.last);
        if elapsed >= backoff {
            None
        } else {
            Some(backoff - elapsed)
        }
    }

    /// Records a failed attempt.
    pub fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        if self.failures.len() >= MAX_TRACKED_IPS && !self.failures.contains_key(&ip) {
            // Drop records old enough not to matter rather than evicting a
            // live lockout.
            self.failures
                .retain(|_, record| now.duration_since(record.last) < MAX_LOCKOUT);
        }
        let entry = self.failures.entry(ip).or_insert(Failures {
            count: 0,
            last: now,
        });
        entry.count = entry.count.saturating_add(1);
        entry.last = now;
    }

    /// Clears an address's failures after a successful login, so one awkward
    /// moment doesn't leave the owner throttled.
    pub fn record_success(&mut self, ip: IpAddr) {
        self.failures.remove(&ip);
    }

    /// Exponential backoff from the attempt count, capped.
    fn backoff(&self, count: u32) -> Duration {
        let steps = count.saturating_sub(FREE_LOGIN_ATTEMPTS).min(6);
        let seconds = 30u64.saturating_mul(1u64 << steps);
        Duration::from_secs(seconds.min(MAX_LOCKOUT.as_secs()))
    }

    /// How many failed attempts are recorded for `ip`.
    pub fn failure_count(&self, ip: IpAddr) -> u32 {
        self.failures.get(&ip).map(|f| f.count).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// A parsed request. Only what this server needs.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Request {
    /// The value of a header, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }

    /// A cookie value by name.
    pub fn cookie(&self, name: &str) -> Option<String> {
        let header = self.header("cookie")?;
        for pair in header.split(';') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once('=') {
                if key.trim() == name {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }

    /// Client address, honouring `X-Forwarded-For` only when the operator has
    /// declared a trusted proxy — otherwise any client could forge its own
    /// address and dodge rate limiting.
    pub fn client_ip(&self, peer: IpAddr, trust_proxy: bool) -> IpAddr {
        if trust_proxy {
            if let Some(forwarded) = self.header("x-forwarded-for") {
                // Left-most entry is the original client in the usual
                // proxy chain format.
                if let Some(first) = forwarded.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
        peer
    }
}

/// Reads one request from `reader`.
///
/// Enforces a line cap and a body cap so a malformed or hostile request can't
/// exhaust memory. Returns `Err` with a message for anything it won't serve.
pub fn read_request(reader: &mut impl BufRead) -> Result<Request, String> {
    let mut line = String::new();
    read_line_capped(reader, &mut line)?;
    let request_line = line.trim_end();
    if request_line.is_empty() {
        return Err("empty request".to_string());
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_uppercase();
    let target = parts.next().ok_or("no path")?;
    // Anything but GET/POST is not something this UI uses.
    if method != "GET" && method != "POST" {
        return Err(format!("unsupported method {method}"));
    }
    // Strip any query string; form data arrives in the body.
    let path = target.split('?').next().unwrap_or("/").to_string();

    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut header_line = String::new();
        read_line_capped(reader, &mut header_line)?;
        let header_line = header_line.trim_end();
        if header_line.is_empty() {
            break;
        }
        if let Some((name, value)) = header_line.split_once(':') {
            // First occurrence wins, so a duplicated header can't override a
            // legitimate one.
            headers
                .entry(name.trim().to_lowercase())
                .or_insert_with(|| value.trim().to_string());
        }
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err("request body too large".to_string());
    }

    let mut body = String::new();
    if length > 0 {
        let mut buffer = vec![0u8; length];
        std::io::Read::read_exact(reader, &mut buffer).map_err(|e| format!("short body: {e}"))?;
        body = String::from_utf8_lossy(&buffer).into_owned();
    }

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn read_line_capped(reader: &mut impl BufRead, out: &mut String) -> Result<(), String> {
    let read = reader
        .read_line(out)
        .map_err(|e| format!("read error: {e}"))?;
    if read == 0 {
        return Err("connection closed".to_string());
    }
    if out.len() > MAX_LINE_BYTES {
        return Err("request line too long".to_string());
    }
    Ok(())
}

/// A response ready to be written.
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: String,
    /// `Set-Cookie` values.
    pub cookies: Vec<String>,
    pub headers: Vec<(String, String)>,
}

impl Response {
    fn new(status: u16, reason: &'static str, content_type: &'static str, body: String) -> Self {
        Response {
            status,
            reason,
            content_type,
            body,
            cookies: Vec::new(),
            headers: Vec::new(),
        }
    }

    pub fn html(body: String) -> Self {
        Response::new(200, "OK", "text/html; charset=utf-8", body)
    }

    pub fn redirect(to: &str) -> Self {
        let mut response = Response::new(303, "See Other", "text/plain; charset=utf-8", String::new());
        response.headers.push(("Location".to_string(), to.to_string()));
        response
    }

    pub fn see_other_with_notice(to: &str, notice: &str) -> Self {
        let mut response = Self::redirect(to);
        response.cookies.push(format!(
            "notice={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=30",
            url_encode(notice)
        ));
        response
    }

    pub fn error(status: u16, reason: &'static str, message: &str) -> Self {
        Response::new(
            status,
            reason,
            "text/plain; charset=utf-8",
            format!("{message}\n"),
        )
    }

    pub fn denial(status: u16, reason: &'static str, message: &str) -> Self {
        Response::new(status, reason, "text/html; charset=utf-8", message.to_string())
    }

    /// Serialises the response, always with `Connection: close`. Each request
    /// gets its own connection, which keeps keep-alive bookkeeping out of a
    /// small server.
    pub fn write_to(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut out = String::new();
        out.push_str(&format!("HTTP/1.1 {} {}\r\n", self.status, self.reason));
        out.push_str(&format!("Content-Type: {}\r\n", self.content_type));
        out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        out.push_str("Connection: close\r\n");
        // A control panel should never be framed, and never leak its path.
        out.push_str("X-Frame-Options: DENY\r\n");
        out.push_str("X-Content-Type-Options: nosniff\r\n");
        out.push_str("Referrer-Policy: no-referrer\r\n");
        out.push_str("Cache-Control: no-store\r\n");
        for cookie in &self.cookies {
            out.push_str(&format!("Set-Cookie: {cookie}\r\n"));
        }
        for (name, value) in &self.headers {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&self.body);
        stream.write_all(out.as_bytes())?;
        stream.flush()
    }
}

/// Percent-encodes a value for use in a cookie or URL.
pub fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            b' ' => out.push_str("%20"),
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Everything a request handler needs.
pub struct WebContext {
    pub state: Arc<Mutex<State>>,
    pub inventory: Arc<Mutex<Inventory>>,
    pub iface: String,
    pub my_ip: String,
    pub sessions: Mutex<Sessions>,
    pub guard: Mutex<LoginGuard>,
    /// Honour `X-Forwarded-For` and mark cookies `Secure`. Enables running
    /// behind a TLS-terminating reverse proxy.
    pub trust_proxy: bool,
    /// Set when the user asks to stop; the accept loop notices and exits.
    pub shutdown: Mutex<bool>,
    /// Checks a password. Injected rather than called directly so the whole
    /// routing and session flow can be tested without a real password file
    /// in `/etc`, which a test can't write to.
    verify: Arc<dyn Fn(&str) -> bool + Send + Sync>,
}

impl WebContext {
    pub fn new(
        state: Arc<Mutex<State>>,
        inventory: Arc<Mutex<Inventory>>,
        iface: String,
        my_ip: String,
        trust_proxy: bool,
    ) -> Self {
        Self::with_verifier(
            state,
            inventory,
            iface,
            my_ip,
            trust_proxy,
            Arc::new(|password: &str| crate::auth::verify_password(password)),
        )
    }

    /// Builds a context with a specific password check, for tests.
    pub fn with_verifier(
        state: Arc<Mutex<State>>,
        inventory: Arc<Mutex<Inventory>>,
        iface: String,
        my_ip: String,
        trust_proxy: bool,
        verify: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    ) -> Self {
        WebContext {
            state,
            inventory,
            iface,
            my_ip,
            sessions: Mutex::new(Sessions::default()),
            guard: Mutex::new(LoginGuard::default()),
            trust_proxy,
            shutdown: Mutex::new(false),
            verify,
        }
    }

    fn check_password(&self, password: &str) -> bool {
        // Serialise hashing globally: each verification costs over a second on
        // purpose, so concurrent attempts would otherwise saturate every core.
        let _serialised = HASH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        (self.verify)(password)
    }

    fn session_cookie_name() -> &'static str {
        "curfew_session"
    }

    fn cookie_attributes(&self, max_age: Option<u64>) -> String {
        // Secure only under a trusted-proxy deployment; setting it without TLS
        // would make the browser drop the cookie and break plain-HTTP use.
        let secure = if self.trust_proxy { "; Secure" } else { "" };
        match max_age {
            Some(seconds) => format!("Path=/; HttpOnly; SameSite=Strict{secure}; Max-Age={seconds}"),
            None => format!("Path=/; HttpOnly; SameSite=Strict{secure}"),
        }
    }
}

/// Runs the server until it's asked to stop. Blocks.
pub fn serve(address: &str, context: Arc<WebContext>) -> std::io::Result<()> {
    let listener = TcpListener::bind(address)?;

    // `curfew` runs as root and this port is reachable from the network, so
    // report exactly what is exposed rather than leaving it implicit.
    let advertised = if address.starts_with("0.0.0.0") || address.starts_with("[::]") {
        format!(
            "http://<this machine's address>:{}",
            listener.local_addr()?.port()
        )
    } else {
        format!("http://{address}")
    };
    println!();
    println!("{BOLD}{CYAN}Curfew web panel{RESET} listening on {advertised}");
    if !context.trust_proxy && !address.starts_with("127.0.0.1") {
        println!("{YELLOW}This is plain HTTP. Don't expose it to the internet —{RESET}");
        println!("{YELLOW}reach it over a VPN, or an `ssh -L` tunnel, instead.{RESET}");
    }
    println!("{DIM}Anything it changes still needs your password.{RESET}");
    println!();

    for incoming in listener.incoming() {
        {
            let shutdown = context
                .shutdown
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *shutdown {
                break;
            }
        }

        let stream = match incoming {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let context = Arc::clone(&context);
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(stream, context) {
                // Client disconnects are normal; don't spam the terminal.
                let message = e.to_string();
                if !message.contains("connection closed")
                    && !message.contains("Broken pipe")
                    && !message.contains("reset by peer")
                {
                    eprintln!("{DIM}web: {message}{RESET}");
                }
            }
        });
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, context: Arc<WebContext>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let peer = stream
        .peer_addr()
        .map(|addr: SocketAddr| addr.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));

    let mut reader = BufReader::new(stream.try_clone()?);
    let request = match read_request(&mut reader) {
        Ok(request) => request,
        Err(message) => {
            let response = Response::error(400, "Bad Request", &message);
            response.write_to(&mut stream)?;
            return Ok(());
        }
    };

    let response = route(&request, peer, &context);
    response.write_to(&mut stream)
}

/// Dispatches a request. Public so the routing table can be exercised in
/// tests without a socket.
pub fn route(request: &Request, peer: IpAddr, context: &Arc<WebContext>) -> Response {
    let now = Instant::now();
    let client = request.client_ip(peer, context.trust_proxy);

    // Expire sessions opportunistically rather than on a timer thread.
    {
        let mut sessions = context
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.prune(now);
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => {
            let Some((token, session)) = authenticated_with_token(request, context, now) else {
                return login_page(None);
            };
            dashboard_page(request, context, &token, &session)
        }
        ("GET", "/login") => login_page(notice_from(request)),
        ("POST", "/login") => do_login(request, client, context, now),
        ("POST", "/logout") => do_logout(request, client, context),
        ("POST", "/sessions/revoke") => do_revoke_session(request, client, context, now),
        ("POST", "/sessions/revoke-others") => do_revoke_others(request, client, context, now),
        ("POST", "/action") => do_action(request, client, context, now),
        ("GET", "/style.css") => Response::new(
            200,
            "OK",
            "text/css; charset=utf-8",
            STYLESHEET.to_string(),
        ),
        ("GET", "/panel.js") => Response::new(
            200,
            "OK",
            "application/javascript; charset=utf-8",
            SCRIPT.to_string(),
        ),
        _ => Response::error(404, "Not Found", "no such page"),
    }
}

fn authenticated(
    request: &Request,
    context: &Arc<WebContext>,
    now: Instant,
) -> Option<Session> {
    authenticated_with_token(request, context, now).map(|(_, session)| session)
}

/// Like [`authenticated`], but also hands back the token — needed to sign out
/// every session *except* the one making the request.
fn authenticated_with_token(
    request: &Request,
    context: &Arc<WebContext>,
    now: Instant,
) -> Option<(String, Session)> {
    let token = request.cookie(WebContext::session_cookie_name())?;
    let mut sessions = context
        .sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    sessions.touch(&token, now).map(|session| (token, session))
}

/// True if a submitted form carries this session's CSRF token.
fn csrf_matches(fields: &HashMap<String, String>, session: &Session) -> bool {
    let provided = fields.get("csrf").map(String::as_str).unwrap_or("");
    crate::sha256::eq_constant_time(provided.as_bytes(), session.csrf.as_bytes())
}

fn notice_from(request: &Request) -> Option<String> {
    request.cookie("notice").map(|value| percent_decode(&value))
}

fn do_login(
    request: &Request,
    client: IpAddr,
    context: &Arc<WebContext>,
    now: Instant,
) -> Response {
    // Throttle before doing any work, so a locked-out address can't make us
    // spend a second hashing.
    //
    // Refusals here are deliberately *not* written to the audit log: an
    // address stuck in a retry loop would fill the log with one repeated line
    // and push out the history that matters. The wrong passwords that caused
    // the lockout are already recorded.
    {
        let mut guard = context
            .guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(remaining) = guard.lockout_remaining(client, now) {
            let seconds = remaining.as_secs().max(1);
            return Response::denial(
                429,
                "Too Many Requests",
                &simple_page(
                    "Too many tries",
                    &format!("Wait {seconds} second(s) and try again."),
                ),
            );
        }
    }

    let fields = parse_form(&request.body);
    let password = fields.get("password").map(String::as_str).unwrap_or("");

    if password.is_empty() {
        return login_page(Some("Enter your password.".to_string()));
    }

    // Serialise hashing: each verification costs over a second on purpose, so
    // concurrent attempts would otherwise saturate every core.
    let verified = context.check_password(password);

    if !verified {
        let mut guard = context
            .guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.record_failure(client, now);
        let attempts = guard.failure_count(client);
        drop(guard);
        // The attempted password is never recorded — only that an attempt
        // happened and where it came from.
        accesslog::record(
            Kind::SignInFailed,
            &client.to_string(),
            &format!("wrong password (attempt {attempts})"),
        );
        return login_page(Some(format!(
            "Wrong password (attempt {attempts})."
        )));
    }

    {
        let mut guard = context
            .guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.record_success(client);
    }

    let started = {
        let mut sessions = context
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.start(now, &client.to_string())
    };
    let Some((token, _session)) = started else {
        // No secure randomness means no safe session token; refusing is the
        // only correct answer.
        return Response::denial(
            500,
            "Internal Server Error",
            &simple_page(
                "Cannot sign in",
                "No secure random source is available on this machine, so a safe \
                 session could not be created.",
            ),
        );
    };

    let mut response = Response::redirect("/");
    response.cookies.push(format!(
        "{}={token}; {}",
        WebContext::session_cookie_name(),
        context.cookie_attributes(Some(SESSION_ABSOLUTE_TIMEOUT.as_secs()))
    ));
    // Recorded so the owner can see every time the panel was opened, and from
    // where — the answer to "is someone else using this?".
    accesslog::record(Kind::SignedIn, &client.to_string(), "");
    response
}

fn do_logout(request: &Request, client: IpAddr, context: &Arc<WebContext>) -> Response {
    if let Some(token) = request.cookie(WebContext::session_cookie_name()) {
        let mut sessions = context
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.end(&token);
        drop(sessions);
        accesslog::record(Kind::SignedOut, &client.to_string(), "");
    }
    let mut response = Response::redirect("/login");
    response.cookies.push(format!(
        "{}=; {}",
        WebContext::session_cookie_name(),
        context.cookie_attributes(Some(0))
    ));
    response
}

/// Ends one other session — how the owner stops someone else using the panel.
fn do_revoke_session(
    request: &Request,
    client: IpAddr,
    context: &Arc<WebContext>,
    now: Instant,
) -> Response {
    let Some((_, session)) = authenticated_with_token(request, context, now) else {
        return Response::denial(
            401,
            "Unauthorized",
            &simple_page("Signed out", "Your session expired. Sign in again."),
        );
    };
    let fields = parse_form(&request.body);
    if !csrf_matches(&fields, &session) {
        return Response::denial(
            403,
            "Forbidden",
            &simple_page(
                "That didn't come from the panel",
                "Reload the page and try again.",
            ),
        );
    }

    let id = fields.get("id").map(String::as_str).unwrap_or("");
    let revoked = {
        let mut sessions = context
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.revoke_prefix(id)
    };

    if revoked > 0 {
        accesslog::record(
            Kind::SessionRevoked,
            &client.to_string(),
            &format!("signed out a session from {id}"),
        );
        Response::see_other_with_notice("/", "That session has been signed out.")
    } else {
        Response::see_other_with_notice(
            "/",
            "That session had already ended.",
        )
    }
}

/// Ends every session except the one making the request.
fn do_revoke_others(
    request: &Request,
    client: IpAddr,
    context: &Arc<WebContext>,
    now: Instant,
) -> Response {
    let Some((token, session)) = authenticated_with_token(request, context, now) else {
        return Response::denial(
            401,
            "Unauthorized",
            &simple_page("Signed out", "Your session expired. Sign in again."),
        );
    };
    let fields = parse_form(&request.body);
    if !csrf_matches(&fields, &session) {
        return Response::denial(
            403,
            "Forbidden",
            &simple_page(
                "That didn't come from the panel",
                "Reload the page and try again.",
            ),
        );
    }

    let revoked = {
        let mut sessions = context
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.revoke_others(&token)
    };

    accesslog::record(
        Kind::SessionRevoked,
        &client.to_string(),
        &format!("signed out {revoked} other session(s)"),
    );
    Response::see_other_with_notice(
        "/",
        &format!("Signed out {revoked} other session(s)."),
    )
}

fn do_action(
    request: &Request,
    client: IpAddr,
    context: &Arc<WebContext>,
    now: Instant,
) -> Response {
    // Every action needs a session. Reaching here without one is either a
    // stale tab or someone poking at the API.
    let Some(session) = authenticated(request, context, now) else {
        return Response::denial(
            401,
            "Unauthorized",
            &simple_page("Signed out", "Your session expired. Sign in again."),
        );
    };
    let fields = parse_form(&request.body);

    // CSRF: the token is only ever handed to a page we served to a
    // signed-in session, so its presence proves the request came from there.
    if !csrf_matches(&fields, &session) {
        return Response::denial(
            403,
            "Forbidden",
            &simple_page(
                "That didn't come from the panel",
                "Reload the page and try again.",
            ),
        );
    }

    let action = match Action::parse(&fields) {
        Ok(action) => action,
        Err(message) => {
            return Response::see_other_with_notice("/", &format!("Nothing changed: {message}"));
        }
    };

    // Stopping restores the network and exits; reply first so the browser
    // isn't left waiting on a dead socket.
    if matches!(action, Action::Stop) {
        *context
            .shutdown
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        let state = Arc::clone(&context.state);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(750));
            devices::cleanup(&state);
        });
        return Response::see_other_with_notice("/", "Stopping Curfew and restoring the network...");
    }

    let notice = match apply_action(&action, context) {
        Ok(notice) => notice,
        Err(message) => format!("Couldn't do that: {message}"),
    };
    crate::state::log_event(&context.state, &action.describe());
    // Who did it, where from — the audit trail for every change.
    accesslog::record(Kind::Action, &client.to_string(), &action.summary());
    Response::see_other_with_notice("/", &notice)
}

/// Executes a validated action. Returns a message for the user.
pub fn apply_action(action: &Action, context: &Arc<WebContext>) -> Result<String, String> {
    let state = &context.state;
    let iface = context.iface.as_str();
    let inventory = Arc::clone(&context.inventory);

    match action {
        Action::GrantFullSpeed { ip } => {
            let mac = devices::grant_full_speed(iface, ip, state);
            let mut inventory = inventory.lock().unwrap_or_else(|p| p.into_inner());
            if inventory.get(&mac).is_none() {
                inventory.seen(&mac, None, now_epoch());
            }
            Ok(format!("{ip} now has full speed, permanently."))
        }
        Action::RevokeFullSpeed { mac } => {
            devices::revoke_full_speed(mac, state);
            Ok(format!("{mac} will be slowed down again shortly."))
        }
        Action::SetDeviceRate { ip, rate } => {
            let mac = crate::state::get_mac(state, iface, ip);
            devices::set_device_mode(
                iface,
                ip,
                &mac,
                Some(DeviceMode::Rate(rate.clone())),
                state,
            );
            Ok(format!("{ip} is now {}.", rate::friendly(rate)))
        }
        Action::BlockDevice { ip } => {
            let mac = crate::state::get_mac(state, iface, ip);
            devices::set_device_mode(iface, ip, &mac, Some(DeviceMode::Block), state);
            Ok(format!("{ip} has no internet now."))
        }
        Action::ClearDevice { ip } => {
            let mac = crate::state::get_mac(state, iface, ip);
            devices::set_device_mode(iface, ip, &mac, None, state);
            Ok(format!("{ip} is back on the household setting."))
        }
        Action::SetHouseholdRate { rate } => {
            devices::set_household_rate(iface, rate, state);
            Ok(format!("Everyone else is now {}.", rate::friendly(rate)))
        }
        Action::Pause { minutes } => {
            devices::set_pause(state, Some(*minutes));
            Ok(format!("Everyone has full speed for {minutes} minute(s)."))
        }
        Action::Resume => {
            devices::set_pause(state, None);
            Ok("The break has ended.".to_string())
        }
        Action::DefenseOn => {
            if !crate::defense::available() {
                return Err("the defense needs `ip` and `arping`".to_string());
            }
            // The monitor loop builds the real plan on its next scan; this
            // just switches the defense on so it starts defending.
            crate::defense::enable(iface, Vec::new());
            Ok("Defense is on. Real addresses will be pinned as soon as a spoofer is seen.".to_string())
        }
        Action::DefenseOff => {
            let removed = crate::defense::disable();
            Ok(format!(
                "Defense is off. {} pin(s) removed.",
                removed.len()
            ))
        }
        Action::Stop => Err("stopping is handled separately".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn login_page(notice: Option<String>) -> Response {
    let notice_html = notice
        .map(|message| format!("<p class=\"notice\">{}</p>", html_escape(&message)))
        .unwrap_or_default();

    Response::html(format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Curfew</title>
<link rel=\"stylesheet\" href=\"/style.css\">
</head>
<body class=\"centred\">
<main class=\"card\">
<h1>Curfew</h1>
<p class=\"dim\">Sign in to change anything.</p>
{notice_html}
<form method=\"post\" action=\"/login\">
<label for=\"password\">Password</label>
<input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" autofocus required>
<button type=\"submit\">Sign in</button>
</form>
</main>
</body>
</html>"
    ))
}

fn simple_page(title: &str, message: &str) -> String {
    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{title}</title>
<link rel=\"stylesheet\" href=\"/style.css\">
</head>
<body class=\"centred\">
<main class=\"card\">
<h1>{}</h1>
<p>{}</p>
<p><a href=\"/\">Back to the panel</a></p>
</main>
</body>
</html>",
        html_escape(title),
        html_escape(message)
    )
}

/// One row of the device table, assembled for rendering.
struct DeviceView {
    ip: String,
    mac: String,
    label: String,
    detail: String,
    status: String,
    status_class: &'static str,
    bytes: Option<u64>,
    exempt: bool,
    randomised_mac: bool,
    sites: Vec<String>,
}

fn dashboard_page(
    request: &Request,
    context: &Arc<WebContext>,
    token: &str,
    session: &Session,
) -> Response {
    let state = &context.state;
    eprintln!("dash: entered");
    let (devices, exempt, allowed, household_rate, pause_left, schedule_desc, active) = {
        let st = devices::lock_state(state);
        eprintln!("dash: state locked");
        let pause_left = st.pause_until.and_then(|until| {
            let now = Instant::now();
            (now < until).then(|| (until - now).as_secs() / 60 + 1)
        });
        let schedule_desc = st
            .schedule
            .as_ref()
            .map(|s| {
                s.windows
                    .iter()
                    .map(|w| w.describe())
                    .collect::<Vec<_>>()
                    .join("  ·  ")
            })
            .unwrap_or_else(|| "none — slowed down all the time".to_string());
        (
            st.devices.clone(),
            st.exempt_online.clone(),
            st.allowed_macs.clone(),
            st.rate.clone(),
            pause_left,
            schedule_desc,
            schedule::is_active(&st.schedule) && pause_left.is_none(),
        )
    };

    let snapshot = crate::tc::snapshot(&context.iface);
    let notice = notice_from(request);
    let device_views = build_device_views(
        state,
        &context.iface,
        &context.inventory,
        &devices,
        &exempt,
        &snapshot,
    );

    let mut rows = String::new();
    for device in &device_views {
        rows.push_str(&device_row_html(device, session));
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"5\" class=\"dim\">No other devices found yet — still looking.<br>\
             <span class=\"dim\">Devices appear here once they're on your Wi-Fi.</span></td></tr>",
        );
    }

    let mut exempt_rows = String::new();
    for mac in &allowed {
        exempt_rows.push_str(&format!(
            "<li><span class=\"mono\">{}</span>
             <form method=\"post\" action=\"/action\" class=\"inline\">
             <input type=\"hidden\" name=\"csrf\" value=\"{}\">
             <input type=\"hidden\" name=\"action\" value=\"revoke\">
             <input type=\"hidden\" name=\"mac\" value=\"{}\">
             <button type=\"submit\" class=\"secondary\">Take it away</button>
             </form></li>",
            html_escape(mac),
            html_escape(&session.csrf),
            html_escape(mac)
        ));
    }
    if exempt_rows.is_empty() {
        exempt_rows.push_str("<li class=\"dim\">Nobody is on the full-speed list.</li>");
    }

    let mut rate_options = String::new();
    for choice in rate::CHOICES {
        let selected = if choice.key == household_rate { " selected" } else { "" };
        rate_options.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            html_escape(choice.key),
            selected,
            html_escape(choice.menu)
        ));
    }

    let status_line = if let Some(minutes) = pause_left {
        format!("Break on — everyone has full speed for about {minutes} more minute(s).")
    } else if active {
        format!("Slowed down. Everyone else is {}.", rate::friendly(&household_rate))
    } else {
        "Bedtime hours are over — everyone has full speed right now.".to_string()
    };

    let hide_this_machine = format!(
        "This machine is {} — it always has full speed, so it isn't listed below.",
        html_escape(&context.my_ip)
    );

    let maker_note = crate::oui::missing_table_hint()
        .map(|hint| format!("<p class=\"dim\">{}</p>", html_escape(hint)))
        .unwrap_or_default();

    // Who has been using this, and what they did.
    let access = access_section(context, token, session);

    let sites_note = match crate::dnswatch::unavailability_reason() {
        Some(reason) => format!("<p class=\"dim\">{}</p>", html_escape(&reason)),
        None => String::new(),
    };

    let body = format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Curfew</title>
<link rel=\"stylesheet\" href=\"/style.css\">
</head>
<body>
<header>
<h1>Curfew</h1>
<form method=\"post\" action=\"/logout\" class=\"inline\">
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
<button type=\"submit\" class=\"secondary\">Sign out</button>
</form>
</header>

<main>
{notice}
<p class=\"status\">{status_line}</p>
<p class=\"dim\">{hide_this_machine}</p>

<section class=\"card\">
<h2>Devices</h2>
<table>
<thead><tr><th>Device</th><th>Address</th><th>Status</th><th>Slowed data</th><th>Do this</th></tr></thead>
<tbody>{rows}</tbody>
</table>
{maker_note}
{sites_note}
</section>

<section class=\"card\">
<h2>Everyone else</h2>
<form method=\"post\" action=\"/action\" class=\"row\">
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
<input type=\"hidden\" name=\"action\" value=\"household_rate\">
<label for=\"rate\">How slow</label>
<select id=\"rate\" name=\"rate\">{rate_options}</select>
<button type=\"submit\">Change</button>
</form>

<form method=\"post\" action=\"/action\" class=\"row\">
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
<input type=\"hidden\" name=\"action\" value=\"pause\">
<label for=\"minutes\">Full speed for</label>
<input type=\"number\" id=\"minutes\" name=\"minutes\" value=\"15\" min=\"1\" max=\"1440\">
<label class=\"dim\">minutes</label>
<button type=\"submit\">Start break</button>
</form>

<form method=\"post\" action=\"/action\" class=\"inline\">
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
<input type=\"hidden\" name=\"action\" value=\"resume\">
<button type=\"submit\" class=\"secondary\">End break</button>
</form>
</section>

<section class=\"card\">
<h2>Always full speed</h2>
<ul class=\"plain\">{exempt_rows}</ul>
</section>

<section class=\"card\">
<h2>Bedtime hours</h2>
<p class=\"mono\">{schedule_desc}</p>
<p class=\"dim\">Change these from the Curfew window on the machine itself.</p>
</section>

{access}

<section class=\"card\">
<h2>Stop Curfew</h2>
<p class=\"dim\">Puts everyone back to normal internet and exits.</p>
<form method=\"post\" action=\"/action\">
<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
<input type=\"hidden\" name=\"action\" value=\"stop\">
<button type=\"submit\" class=\"danger\" data-confirm=\"Stop Curfew and give everyone full speed?\">Stop Curfew</button>
</form>
</section>
</main>

<footer class=\"dim\">
Plain HTTP — reach this over a VPN or an <code>ssh -L</code> tunnel, never the open internet.
</footer>
<script src=\"/panel.js\"></script>
</body>
</html>",
        csrf = html_escape(&session.csrf),
        notice = notice
            .map(|m| format!("<p class=\"notice\">{}</p>", html_escape(&m)))
            .unwrap_or_default(),
    );

    Response::html(body)
}

/// "3 min ago" — for session ages and the audit trail. A re-export of the
/// shared formatter under the name its call sites already used.
use crate::inventory::humanise_age as humanise_ago;

/// The "Who's using Curfew" card.
///
/// Two questions in one place: who is signed in *right now*, and who has ever
/// signed in or tried to. That is the whole point of the feature — the owner
/// being able to see when someone else has been in here.
fn access_section(context: &Arc<WebContext>, token: &str, session: &Session) -> String {
    let csrf = html_escape(&session.csrf);
    let now = Instant::now();
    let my_id: String = token.chars().take(SESSION_ID_CHARS).collect();

    let sessions = {
        let mut guard = context
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.list(now)
    };

    let mut session_rows = String::new();
    let mut others = 0usize;
    for info in &sessions {
        let mine = info.id == my_id;
        if !mine {
            others += 1;
        }
        let marker = if mine {
            " <span class=\"pill\">this browser</span>"
        } else {
            ""
        };
        // Offering to sign yourself out here is redundant (there's a button in
        // the header), so the action column stays empty for your own session.
        let action = if mine {
            String::new()
        } else {
            format!(
                "<form method=\"post\" action=\"/sessions/revoke\" class=\"inline\">\
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                 <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                 <button type=\"submit\" class=\"danger\" \
                 data-confirm=\"Sign that session out?\">Sign out</button></form>",
                id = html_escape(&info.id)
            )
        };
        session_rows.push_str(&format!(
            "<tr><td class=\"mono\">{}{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&info.id),
            marker,
            html_escape(&info.ip),
            humanise_ago(info.age_secs),
            humanise_ago(info.idle_secs),
            action
        ));
    }
    if session_rows.is_empty() {
        session_rows.push_str("<tr><td colspan=\"5\" class=\"dim\">No sessions.</td></tr>");
    }

    // Only worth offering when there is actually someone else signed in.
    let revoke_others = if others > 0 {
        format!(
            "<form method=\"post\" action=\"/sessions/revoke-others\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button type=\"submit\" class=\"danger\" \
             data-confirm=\"Sign out all {others} other session(s)?\">\
             Sign out everyone else</button></form>"
        )
    } else {
        String::new()
    };

    let entries: Vec<crate::accesslog::Entry> =
        accesslog::with_log(|log| log.recent(12).into_iter().cloned().collect());
    let mut trail = String::new();
    if entries.is_empty() {
        trail.push_str("<li class=\"dim\">Nothing recorded yet.</li>");
    }
    for entry in &entries {
        let class = if entry.kind.is_alert() { "bad" } else { "dim" };
        trail.push_str(&format!(
            "<li class=\"{class}\">{}</li>",
            html_escape(&entry.describe())
        ));
    }

    let sources = accesslog::with_log(|log| log.sign_in_sources());
    let mut who = String::new();
    for (actor, count, at) in sources.iter().take(8) {
        who.push_str(&format!(
            "<li><span class=\"mono\">{}</span> <span class=\"dim\">— {} sign-in(s), last {}</span></li>",
            html_escape(actor),
            count,
            html_escape(&accesslog::when_text(*at))
        ));
    }
    if who.is_empty() {
        who.push_str("<li class=\"dim\">No sign-ins recorded yet.</li>");
    }

    // Whether something else on this network is intercepting traffic. This is
    // the active check, distinct from the panel scan elsewhere on the page.
    let arp_section = arp_spoofing_section(session);

    format!(
        "<section class=\"card\">
<h2>Who's using Curfew</h2>
<p class=\"dim\">Every sign-in and every change is recorded here, with where it came from.
A wrong password is never stored — only that an attempt happened.</p>
<table>
<thead><tr><th>Session</th><th>From</th><th>Signed in</th><th>Last used</th><th></th></tr></thead>
<tbody>{session_rows}</tbody>
</table>
{revoke_others}
<h3>Recent activity</h3>
<ul class=\"plain\">{trail}</ul>
<h3>Who has signed in</h3>
<ul class=\"plain\">{who}</ul>
</section>
{arp_section}"
    )
}

/// The "someone else spoofing the network" card.
///
/// Kept in its own function because it's the one section that reports on
/// activity rather than settings, and it has three distinct states: watching
/// and clear, watching and alarmed, and not watching at all.
fn arp_spoofing_section(session: &Session) -> String {
    let csrf = html_escape(&session.csrf);

    // The defense card sits with this one: detection and response belong
    // together on the page.
    let defense_html = if !crate::defense::available() {
        String::new()
    } else {
        let pins = crate::defense::list_pins();
        let (status, action) = if crate::defense::is_enabled() {
            let listing = if pins.is_empty() {
                "<li class=\"dim\">Nothing pinned yet — no spoofer has been detected.</li>"
                    .to_string()
            } else {
                pins.iter()
                    .map(|pin| {
                        format!(
                            "<li class=\"mono good\">{}  {}  <span class=\"dim\">({})</span></li>",
                            html_escape(&pin.ip),
                            html_escape(&pin.mac),
                            html_escape(pin.reason.label())
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("")
            };
            (
                format!(
                    "<p class=\"good\">Defense is on.</p>\
                     <p class=\"dim\">The real hardware address of the router and of any device \
                     being interfered with is pinned, so a spoofer's replies are ignored. \
                     Re-asserted on every scan.</p>\
                     <ul class=\"plain\">{listing}</ul>"
                ),
                format!(
                    "<form method=\"post\" action=\"/action\">\
                     <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                     <input type=\"hidden\" name=\"action\" value=\"defense_off\">\
                     <button type=\"submit\" class=\"secondary\" \
                     data-confirm=\"Turn the defense off and unpin everything?\">\
                     Turn defense off</button></form>"
                ),
            )
        } else {
            (
                "<p class=\"dim\">Defense is off. If someone is throttling devices on this \
                 network, Curfew will report it but not intervene.</p>"
                    .to_string(),
                format!(
                    "<form method=\"post\" action=\"/action\">\
                     <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                     <input type=\"hidden\" name=\"action\" value=\"defense_on\">\
                     <button type=\"submit\">Turn defense on</button></form>"
                ),
            )
        };
        format!(
            "<section class=\"card\"><h2>Defense against a spoofer</h2>{status}{action}</section>"
        )
    };

    if !crate::arpwatch::is_running() {
        return match crate::arpwatch::unavailability_reason() {
            Some(reason) => format!(
                "<section class=\"card\"><h2>Someone else spoofing the network</h2>\
                 <p class=\"dim\">{}</p></section>{defense_html}",
                html_escape(&reason)
            ),
            None => defense_html,
        };
    }

    let findings: Vec<String> = crate::arpwatch::with_watcher(|watcher| {
        watcher.findings(6).iter().map(|f| f.describe()).collect()
    })
    .unwrap_or_default();

    let contested: Vec<String> = crate::arpwatch::with_watcher(|watcher| {
        watcher
            .contested()
            .iter()
            .map(|binding| format!("{}  ({})", binding.ip, binding.macs.join(" and ")))
            .collect()
    })
    .unwrap_or_default();

    let mut list = String::new();
    if findings.is_empty() {
        list.push_str(
            "<li class=\"dim\">Nothing suspicious seen. Curfew doesn't report its own \
             throttling — only another machine doing the same thing.</li>",
        );
    }
    for text in &findings {
        list.push_str(&format!("<li class=\"bad\">{}</li>", html_escape(text)));
    }

    let contested_html = if contested.is_empty() {
        String::new()
    } else {
        format!(
            "<h3>Addresses claimed twice</h3><ul class=\"plain\">{}</ul>",
            contested
                .iter()
                .map(|text| format!("<li class=\"mono bad\">{}</li>", html_escape(text)))
                .collect::<Vec<_>>()
                .join("")
        )
    };

    format!(
        "<section class=\"card\">\n\
         <h2>Someone else spoofing the network</h2>\n\
         <p class=\"dim\">Watching ARP for another machine intercepting your devices — the \
         signature of a second throttling tool.</p>\n\
         <ul class=\"plain\">{list}</ul>\n\
         {contested_html}\n\
         </section>\n\
         {defense_html}"
    )
}

fn build_device_views(
    state: &Arc<Mutex<State>>,
    _iface: &str,
    inventory: &Arc<Mutex<Inventory>>,
    throttled: &[String],
    exempt: &[String],
    snapshot: &crate::tc::Snapshot,
) -> Vec<DeviceView> {
    let now = now_epoch();
    let mut views = Vec::new();
    let order: Vec<(String, bool)> = throttled
        .iter()
        .map(|ip| (ip.clone(), false))
        .chain(exempt.iter().map(|ip| (ip.clone(), true)))
        .collect();

    for (ip, exempt_device) in order {
        // Read everything needed from the shared state in one lock, then let
        // it go before touching the inventory.
        let (mac, nickname, status, blocked) = {
            let st = devices::lock_state(state);
            let mac = st.mac_of(&ip).unwrap_or_else(|| "unknown".to_string());
            let nickname = st.names.get(&mac).cloned();
            let status = if exempt_device {
                "full speed".to_string()
            } else if st.is_blocked(&ip) {
                "no internet".to_string()
            } else {
                rate::friendly(&st.effective_rate(&ip)).to_string()
            };
            let blocked = st.is_blocked(&ip);
            (mac, nickname, status, blocked)
        };

        let (label, detail) = {
            let inventory = inventory.lock().unwrap_or_else(|p| p.into_inner());
            let record = inventory.get(&mac);
            let name = nickname
                .clone()
                .or_else(|| record.and_then(|r| r.hostname.clone()))
                .unwrap_or_else(|| "Unnamed device".to_string());

            let mut parts: Vec<String> = Vec::new();
            if let Some(kind) = record.and_then(|r| r.kind()) {
                parts.push(kind.to_string());
            }
            if let Some(vendor) = record.and_then(|r| r.vendor()) {
                parts.push(vendor);
            }
            if let Some(record) = record {
                parts.push(record.last_seen_phrase(now));
            }
            (name, parts.join(" · "))
        };

        views.push(DeviceView {
            ip: ip.clone(),
            mac: mac.clone(),
            label,
            detail,
            status,
            status_class: if exempt_device {
                "good"
            } else if blocked {
                "bad"
            } else {
                "warn"
            },
            bytes: snapshot.for_device(&ip),
            exempt: exempt_device,
            randomised_mac: crate::oui::is_randomised(&mac),
            sites: crate::dnswatch::with_log(|log| log.domains_for(&ip).into_iter().take(4).collect()),
        });
    }

    views
}

fn device_row_html(device: &DeviceView, session: &Session) -> String {
    let csrf = html_escape(&session.csrf);
    let ip = html_escape(&device.ip);
    let mac = html_escape(&device.mac);

    // Actions for this device. Every one is a POST carrying the CSRF token.
    let mut actions = String::new();
    if device.exempt {
        actions.push_str(&format!(
            "<form method=\"post\" action=\"/action\" class=\"inline\">
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
             <input type=\"hidden\" name=\"action\" value=\"revoke\">
             <input type=\"hidden\" name=\"mac\" value=\"{mac}\">
             <button type=\"submit\" class=\"secondary\">Slow down</button></form>"
        ));
    } else {
        actions.push_str(&format!(
            "<form method=\"post\" action=\"/action\" class=\"inline\">
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
             <input type=\"hidden\" name=\"action\" value=\"grant\">
             <input type=\"hidden\" name=\"ip\" value=\"{ip}\">
             <button type=\"submit\" class=\"secondary\">Full speed</button></form>"
        ));
        if device.status == "no internet" {
            actions.push_str(&format!(
                "<form method=\"post\" action=\"/action\" class=\"inline\">
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
                 <input type=\"hidden\" name=\"action\" value=\"clear_device\">
                 <input type=\"hidden\" name=\"ip\" value=\"{ip}\">
                 <button type=\"submit\" class=\"secondary\">Unblock</button></form>"
            ));
        } else {
            actions.push_str(&format!(
                "<form method=\"post\" action=\"/action\" class=\"inline\">
                 <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">
                 <input type=\"hidden\" name=\"action\" value=\"block\">
                 <input type=\"hidden\" name=\"ip\" value=\"{ip}\">
                 <button type=\"submit\" class=\"danger\" data-confirm=\"Cut off the internet for {ip}?\">Block</button></form>"
            ));
        }
    }

    let random_warning = if device.randomised_mac {
        "<span class=\"pill warn\" title=\"This device uses a private, randomised Wi-Fi address, so its settings may not stick. Turn off 'Private Wi-Fi Address' for your network in the device's settings.\">random MAC</span>"
    } else {
        ""
    };

    let sites = if device.sites.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"sites dim\">recently: {}</div>",
            device
                .sites
                .iter()
                .map(|s| html_escape(s))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let bytes = match device.bytes {
        Some(bytes) => crate::ui::format_bytes(bytes),
        None => "—".to_string(),
    };

    format!(
        "<tr>
<td><strong>{}</strong><div class=\"dim\">{}</div>{}{}</td>
<td class=\"mono\">{}</td>
<td class=\"{}\">{}</td>
<td class=\"mono\">{}</td>
<td class=\"actions\">{}</td>
</tr>",
        html_escape(&device.label),
        html_escape(&device.detail),
        random_warning,
        sites,
        ip,
        device.status_class,
        html_escape(&device.status),
        bytes,
        actions
    )
}

/// Static stylesheet, served separately so the HTML stays readable.
const STYLESHEET: &str = include_str!("web.css");

/// The panel's only script; optional, since every action is a plain form.
const SCRIPT: &str = include_str!("panel.js");

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // -- action parsing ---------------------------------------------------

    #[test]
    fn parses_a_grant_action() {
        assert_eq!(
            Action::parse(&fields(&[("action", "grant"), ("ip", "192.168.1.27")])),
            Ok(Action::GrantFullSpeed {
                ip: "192.168.1.27".to_string()
            })
        );
    }

    #[test]
    fn rejects_an_unknown_action_rather_than_defaulting() {
        assert!(Action::parse(&fields(&[("action", "delete_everything")])).is_err());
        assert!(Action::parse(&fields(&[])).is_err());
    }

    #[test]
    fn rejects_an_ip_that_could_smuggle_extra_arguments() {
        // These values end up in a `tc` command line, so anything but a bare
        // address must be refused.
        for bad in [
            "192.168.1.1 dev wlan0", // extra arguments
            "192.168.1.1; rm -rf /",
            "$(whoami)",
            "192.168.1.256",
            "192.168.1",
            "192.168.1.1/24",
            "example.com",
            "",
            "::1",
        ] {
            let result = Action::parse(&fields(&[("action", "block"), ("ip", bad)]));
            assert!(result.is_err(), "{bad:?} should be rejected, got {result:?}");
        }
    }

    #[test]
    fn accepts_ordinary_addresses() {
        for good in ["192.168.1.27", "10.0.0.1", "0.0.0.0", "255.255.255.255"] {
            assert!(is_plausible_ipv4(good), "{good} should be accepted");
        }
    }

    #[test]
    fn rejects_a_mac_that_is_not_a_mac() {
        assert!(Action::parse(&fields(&[("action", "revoke"), ("mac", "nope")])).is_err());
        assert_eq!(
            Action::parse(&fields(&[
                ("action", "revoke"),
                ("mac", "00-14-51-11-22-33")
            ])),
            Ok(Action::RevokeFullSpeed {
                mac: "00:14:51:11:22:33".to_string()
            }),
            "a valid MAC in Windows form is normalised"
        );
    }

    #[test]
    fn rejects_an_unoffered_speed() {
        assert!(Action::parse(&fields(&[
            ("action", "household_rate"),
            ("rate", "0kbit")
        ]))
        .is_err());
        assert!(Action::parse(&fields(&[
            ("action", "household_rate"),
            ("rate", "10kbit")
        ]))
        .is_ok());
    }

    #[test]
    fn bounds_the_break_duration() {
        // A typo shouldn't turn the throttle off for a week.
        assert!(Action::parse(&fields(&[("action", "pause"), ("minutes", "0")])).is_err());
        assert!(Action::parse(&fields(&[("action", "pause"), ("minutes", "1441")])).is_err());
        assert!(Action::parse(&fields(&[("action", "pause"), ("minutes", "abc")])).is_err());
        assert!(Action::parse(&fields(&[("action", "pause"), ("minutes", "-5")])).is_err());
        assert_eq!(
            Action::parse(&fields(&[("action", "pause"), ("minutes", "30")])),
            Ok(Action::Pause { minutes: 30 })
        );
    }

    // -- form decoding ----------------------------------------------------

    #[test]
    fn decodes_form_fields() {
        let parsed = parse_form("action=grant&ip=192.168.1.27");
        assert_eq!(parsed.get("action").map(String::as_str), Some("grant"));
        assert_eq!(parsed.get("ip").map(String::as_str), Some("192.168.1.27"));
    }

    #[test]
    fn decodes_percent_escapes_and_plus_as_space() {
        let parsed = parse_form("notice=Hello+there%21&x=%2Fetc%2Fpasswd");
        assert_eq!(parsed.get("notice").map(String::as_str), Some("Hello there!"));
        assert_eq!(parsed.get("x").map(String::as_str), Some("/etc/passwd"));
    }

    #[test]
    fn keeps_an_empty_field_distinct_from_a_missing_one() {
        let parsed = parse_form("password=&other=1");
        assert_eq!(parsed.get("password").map(String::as_str), Some(""));
        assert_eq!(parsed.get("absent"), None);
    }

    #[test]
    fn handles_malformed_form_data_without_panicking() {
        assert!(parse_form("").is_empty());
        assert!(parse_form("&&&").is_empty());
        // A stray percent is literal, not a failure.
        assert_eq!(parse_form("a=100%").get("a").map(String::as_str), Some("100%"));
        assert_eq!(parse_form("a=%zz").get("a").map(String::as_str), Some("%zz"));
        // A key with no value still registers.
        assert_eq!(parse_form("flag").get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn does_not_let_a_later_duplicate_override_an_earlier_field() {
        // Otherwise a crafted body could replace an already-validated value.
        let parsed = parse_form("ip=1.2.3.4&ip=9.9.9.9");
        assert_eq!(parsed.get("ip").map(String::as_str), Some("1.2.3.4"));
    }

    // -- escaping ---------------------------------------------------------

    #[test]
    fn escapes_html_so_a_device_name_cannot_inject_script() {
        // Hostnames come from the network; this is the line between a device
        // being able to run script in the owner's browser or not.
        let hostile = "<script>fetch('/action')</script>";
        let escaped = html_escape(hostile);
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn escapes_every_html_metacharacter() {
        assert_eq!(html_escape("&"), "&amp;");
        assert_eq!(html_escape("<"), "&lt;");
        assert_eq!(html_escape(">"), "&gt;");
        assert_eq!(html_escape("\""), "&quot;");
        assert_eq!(html_escape("'"), "&#39;");
        assert_eq!(html_escape("normal text"), "normal text");
    }

    #[test]
    fn url_encoding_round_trips_through_percent_decoding() {
        let original = "Stopped: 3 devices. % done & more?";
        let encoded = url_encode(original);
        assert!(!encoded.contains(' '), "spaces must be encoded");
        assert_eq!(percent_decode(&encoded), original);
    }

    // -- sessions ---------------------------------------------------------

    #[test]
    fn a_session_is_accepted_while_fresh() {
        let mut sessions = Sessions::default();
        let now = Instant::now();
        let (token, _) = sessions.start(now, "192.168.1.31").expect("random source");
        assert!(sessions.touch(&token, now).is_some());
    }

    #[test]
    fn an_unknown_token_is_rejected() {
        let mut sessions = Sessions::default();
        assert!(sessions.touch("not-a-token", Instant::now()).is_none());
    }

    #[test]
    fn a_session_expires_after_being_idle() {
        let mut sessions = Sessions::default();
        let now = Instant::now();
        let (token, _) = sessions.start(now, "192.168.1.31").expect("random source");
        let later = now + SESSION_IDLE_TIMEOUT + Duration::from_secs(1);
        assert!(sessions.touch(&token, later).is_none());
    }

    #[test]
    fn a_session_expires_even_if_it_is_continuously_used() {
        let mut sessions = Sessions::default();
        let start = Instant::now();
        let (token, _) = sessions.start(start, "192.168.1.31").expect("random source");
        // Keep it busy, but past the absolute cap.
        let mut now = start;
        for _ in 0..20 {
            now += Duration::from_secs(60 * 60);
            sessions.touch(&token, now);
        }
        assert!(
            sessions.touch(&token, now).is_none(),
            "a stolen cookie must not live forever"
        );
    }

    #[test]
    fn ending_a_session_revokes_it() {
        let mut sessions = Sessions::default();
        let now = Instant::now();
        let (token, _) = sessions.start(now, "192.168.1.31").expect("random source");
        sessions.end(&token);
        assert!(sessions.touch(&token, now).is_none());
    }

    #[test]
    fn each_session_gets_a_distinct_token_and_csrf_value() {
        let mut sessions = Sessions::default();
        let now = Instant::now();
        let (token_a, a) = sessions.start(now, "192.168.1.31").unwrap();
        let (token_b, b) = sessions.start(now, "192.168.1.31").unwrap();
        assert_ne!(token_a, token_b);
        assert_ne!(a.csrf, b.csrf);
        assert!(token_a.len() >= 64, "32 bytes of hex");
    }

    // -- login throttling -------------------------------------------------

    #[test]
    fn a_few_failures_do_not_lock_anyone_out() {
        let mut guard = LoginGuard::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..FREE_LOGIN_ATTEMPTS {
            assert!(guard.lockout_remaining(ip, now).is_none());
            guard.record_failure(ip, now);
        }
    }

    #[test]
    fn repeated_failures_start_a_lockout() {
        let mut guard = LoginGuard::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..=FREE_LOGIN_ATTEMPTS {
            guard.record_failure(ip, now);
        }
        assert!(guard.lockout_remaining(ip, now).is_some());
    }

    #[test]
    fn the_lockout_grows_and_then_eases() {
        let mut guard = LoginGuard::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..4 {
            guard.record_failure(ip, now);
        }
        let first = guard.lockout_remaining(ip, now).unwrap();
        for _ in 0..3 {
            guard.record_failure(ip, now);
        }
        let later = guard.lockout_remaining(ip, now).unwrap();
        assert!(later > first, "backoff should grow: {first:?} -> {later:?}");

        // And it must expire, so the owner isn't locked out forever.
        let much_later = now + MAX_LOCKOUT + Duration::from_secs(1);
        assert!(guard.lockout_remaining(ip, much_later).is_none());
    }

    #[test]
    fn the_lockout_is_capped() {
        let mut guard = LoginGuard::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..100 {
            guard.record_failure(ip, now);
        }
        let remaining = guard.lockout_remaining(ip, now).unwrap();
        assert!(
            remaining <= MAX_LOCKOUT,
            "a determined attacker shouldn't lock the owner out for longer than {MAX_LOCKOUT:?}"
        );
    }

    #[test]
    fn a_successful_login_clears_the_throttle() {
        let mut guard = LoginGuard::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..10 {
            guard.record_failure(ip, now);
        }
        guard.record_success(ip);
        assert!(guard.lockout_remaining(ip, now).is_none());
        assert_eq!(guard.failure_count(ip), 0);
    }

    #[test]
    fn one_address_being_throttled_does_not_affect_another() {
        let mut guard = LoginGuard::default();
        let bad: IpAddr = "10.0.0.1".parse().unwrap();
        let good: IpAddr = "10.0.0.2".parse().unwrap();
        let now = Instant::now();
        for _ in 0..10 {
            guard.record_failure(bad, now);
        }
        assert!(guard.lockout_remaining(good, now).is_none());
    }

    // -- request parsing --------------------------------------------------

    fn parse(raw: &str) -> Result<Request, String> {
        let mut reader = BufReader::new(raw.as_bytes());
        read_request(&mut reader)
    }

    #[test]
    fn parses_a_get_request() {
        let request = parse("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/");
        assert_eq!(request.header("host"), Some("localhost"));
        assert!(request.body.is_empty());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let request = parse("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!(request.header("Content-Length"), Some("0"));
        assert_eq!(request.header("content-length"), Some("0"));
    }

    #[test]
    fn parses_a_post_body() {
        let request = parse(
            "POST /login HTTP/1.1\r\nContent-Length: 15\r\n\r\npassword=secret",
        )
        .unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, "password=secret");
    }

    #[test]
    fn strips_the_query_string_from_the_path() {
        let request = parse("GET /?a=b HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(request.path, "/");
    }

    #[test]
    fn extracts_a_cookie_by_name() {
        let request = parse(
            "GET / HTTP/1.1\r\nCookie: other=1; curfew_session=abc123; notice=hi\r\n\r\n",
        )
        .unwrap();
        assert_eq!(request.cookie("curfew_session").as_deref(), Some("abc123"));
        assert_eq!(request.cookie("notice").as_deref(), Some("hi"));
        assert_eq!(request.cookie("missing"), None);
    }

    #[test]
    fn rejects_an_enormous_body_before_reading_it() {
        let raw = format!(
            "POST /action HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert!(parse(&raw).is_err(), "must refuse rather than allocate");
    }

    #[test]
    fn rejects_an_enormous_header_line() {
        let raw = format!("GET / HTTP/1.1\r\nX-Big: {}\r\n\r\n", "a".repeat(MAX_LINE_BYTES + 10));
        assert!(parse(&raw).is_err());
    }

    #[test]
    fn rejects_methods_it_does_not_serve() {
        assert!(parse("DELETE / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse("PUT / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_an_empty_request() {
        assert!(parse("").is_err());
    }

    #[test]
    fn a_duplicated_header_does_not_override_the_first() {
        let request = parse("POST / HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 9\r\n\r\nab=1")
            .unwrap();
        assert_eq!(request.body, "ab=1");
    }

    #[test]
    fn forwarded_headers_are_ignored_unless_a_proxy_is_trusted() {
        // Otherwise any client could forge its address and dodge throttling.
        let request = parse(
            "GET / HTTP/1.1\r\nX-Forwarded-For: 203.0.113.5, 10.0.0.1\r\n\r\n",
        )
        .unwrap();
        let peer: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(request.client_ip(peer, false), peer);
        assert_eq!(
            request.client_ip(peer, true),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_malformed_forwarded_header_falls_back_to_the_peer() {
        let request = parse("GET / HTTP/1.1\r\nX-Forwarded-For: garbage\r\n\r\n").unwrap();
        let peer: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(request.client_ip(peer, true), peer);
    }

    // -- routing and the security boundary ---------------------------------
    //
    // These drive `route` directly, which is the whole request pipeline minus
    // the socket: parsing, authentication, CSRF, and action execution.

    /// A context whose password check accepts exactly one password.
    fn test_context(password: &'static str) -> Arc<WebContext> {
        let state = Arc::new(Mutex::new(State::new(
            "wlan0".to_string(),
            "192.168.1.1".to_string(),
            "10kbit".to_string(),
        )));
        let inventory = Arc::new(Mutex::new(Inventory::default()));
        Arc::new(WebContext::with_verifier(
            state,
            inventory,
            "wlan0".to_string(),
            "192.168.1.42".to_string(),
            false,
            Arc::new(move |candidate: &str| candidate == password),
        ))
    }

    fn peer() -> IpAddr {
        "192.168.1.50".parse().unwrap()
    }

    fn get(path: &str) -> Request {
        parse(&format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")).unwrap()
    }

    fn post(path: &str, body: &str, cookie: Option<&str>) -> Request {
        let cookie_header = cookie
            .map(|value| format!("Cookie: {value}\r\n"))
            .unwrap_or_default();
        parse(&format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n{cookie_header}\r\n{body}",
            body.len()
        ))
        .unwrap()
    }

    /// Signs in and returns the session cookie to send on later requests.
    fn sign_in(context: &Arc<WebContext>, password: &str) -> String {
        let response = route(
            &post("/login", &format!("password={password}"), None),
            peer(),
            context,
        );
        assert_eq!(response.status, 303, "login should redirect");
        assert!(!context.sessions.lock().unwrap().entries.is_empty());
        let cookie = response
            .cookies
            .iter()
            .find(|c| c.starts_with("curfew_session="))
            .expect("a session cookie")
            .clone();
        // "curfew_session=<token>; Path=/; ..." -> "curfew_session=<token>"
        cookie.split(';').next().unwrap().to_string()
    }

    fn csrf_for(context: &Arc<WebContext>, session_cookie: &str) -> String {
        let token = session_cookie.split('=').nth(1).unwrap().to_string();
        let mut sessions = context.sessions.lock().unwrap();
        sessions.touch(&token, Instant::now()).unwrap().csrf
    }

    #[test]
    fn an_unauthenticated_visitor_gets_the_login_page_and_nothing_else() {
        let context = test_context("hunter2");
        let response = route(&get("/"), peer(), &context);
        assert_eq!(response.status, 200);
        assert!(response.body.contains("name=\"password\""), "it's the login page");
        // No device data may leak to a signed-out visitor.
        assert!(!response.body.contains("192.168.1.42"));
    }

    #[test]
    fn the_state_api_route_is_gone_so_its_now_a_404() {
        // The panel is server-rendered forms only; the JSON state endpoint was
        // never called by anything, so it was removed. This pins that: a
        // reintroduced endpoint nobody uses is just attack surface.
        let context = test_context("hunter2");
        let response = route(&get("/api/state"), peer(), &context);
        assert_eq!(response.status, 404);
    }

    /// Renders the dashboard so a human can open it in a browser and confirm
    /// it looks right. Ignored because it writes a file rather than asserting.
    ///
    /// `cargo test -- --ignored --nocapture render_dashboard_to_file`
    #[test]
    #[ignore = "writes /tmp/curfew-dashboard.html for visual checking"]
    fn render_dashboard_to_file() {
        eprintln!("step 1: building context");
        let context = test_context("hunter2");
        std::fs::write("/tmp/curfew-progress.txt", "context-built\n").unwrap();
        eprintln!("step 2: signing in");
        let cookie = sign_in(&context, "hunter2");
        std::fs::write("/tmp/curfew-progress.txt", "signed-in\n").unwrap();
        eprintln!("step 3: seeding devices");
        // A couple of devices so the table isn't empty.
        {
            let mut st = devices::lock_state(&context.state);
            st.devices.push("192.168.1.27".to_string());
            st.devices.push("192.168.1.144".to_string());
            st.exempt_online.push("192.168.1.7".to_string());
            st.names.insert("00:14:51:11:22:33".into(), "Kid's iPad".into());
        }
        // remember_mac takes the State lock itself, so it must be called
        // OUTSIDE the block above — re-locking the non-reentrant mutex inside
        // deadlocks the test. That was the hang.
        crate::state::remember_mac(&context.state, "192.168.1.27", "0a:11:22:33:44:55");
        crate::state::remember_mac(&context.state, "192.168.1.144", "00:14:51:11:22:33");
        let mut request = get("/");
        std::fs::write("/tmp/curfew-progress.txt", "got-request\n").unwrap();
        request
            .headers
            .insert("cookie".to_string(), cookie.clone());
        std::fs::write("/tmp/curfew-progress.txt", "step4a\n").unwrap();
        eprintln!("step 4a: tc::snapshot probe");
        let snap = crate::tc::snapshot(&context.iface);
        std::fs::write("/tmp/curfew-progress.txt", "step4b\n").unwrap();
        eprintln!("step 4b: snapshot ok ({} classes)", snap.classes.len());
        eprintln!("step 4c: building dashboard directly (bypassing route)");
        let token = cookie.split('=').nth(1).unwrap().to_string();
        let session = {
            let mut sessions = context
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            sessions
                .touch(&token, Instant::now())
                .expect("session should be live")
        };
        let response = dashboard_page(&request, &context, &token, &session);
        eprintln!("step 5: dashboard built ({} bytes)", response.body.len());
        std::fs::write("/tmp/curfew-dashboard.html", &response.body).unwrap();
        println!("wrote /tmp/curfew-dashboard.html ({} bytes)", response.body.len());
    }

    /// Renders the login page the same way.
    #[test]
    #[ignore = "writes /tmp/curfew-login.html for visual checking"]
    fn render_login_to_file() {
        let response = login_page(None);
        std::fs::write("/tmp/curfew-login.html", &response.body).unwrap();
        println!("wrote /tmp/curfew-login.html ({} bytes)", response.body.len());
    }

    #[test]
    fn a_wrong_password_does_not_start_a_session() {
        let context = test_context("hunter2");
        let response = route(&post("/login", "password=wrong", None), peer(), &context);
        assert_eq!(response.status, 200, "back to the login page");
        assert!(context.sessions.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn a_correct_password_starts_a_session_with_a_hardened_cookie() {
        let context = test_context("hunter2");
        let response = route(&post("/login", "password=hunter2", None), peer(), &context);
        let cookie = response
            .cookies
            .iter()
            .find(|c| c.starts_with("curfew_session="))
            .expect("a session cookie");
        // The flags are what stop the token being read by script or sent
        // cross-site.
        assert!(cookie.contains("HttpOnly"), "cookie was: {cookie}");
        assert!(cookie.contains("SameSite=Strict"), "cookie was: {cookie}");
        assert!(cookie.contains("Max-Age="), "cookie was: {cookie}");
    }

    #[test]
    fn a_signed_in_visitor_sees_the_panel() {
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        let response = route(&get("/"), peer(), &context);
        assert!(
            response.status == 200 && response.body.contains("Curfew"),
            "a valid session cookie should reach the panel"
        );
        // Now send it properly, as a browser would.
        let mut request = get("/");
        request
            .headers
            .insert("cookie".to_string(), cookie.clone());
        let response = route(&request, peer(), &context);
        assert!(response.body.contains("Devices"), "should show the panel");
    }

    #[test]
    fn every_action_requires_a_session() {
        let context = test_context("hunter2");
        let response = route(
            &post("/action", "action=pause&minutes=15", None),
            peer(),
            &context,
        );
        assert_eq!(response.status, 401, "no session, no action");
        // And nothing happened.
        assert!(devices::lock_state(&context.state).pause_until.is_none());
    }

    #[test]
    fn an_action_without_the_csrf_token_is_refused() {
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        // Correct session, but the token is missing — as it would be in a
        // cross-site forgery.
        let response = route(
            &post("/action", "action=pause&minutes=15", Some(&cookie)),
            peer(),
            &context,
        );
        assert_eq!(response.status, 403);
        assert!(
            devices::lock_state(&context.state).pause_until.is_none(),
            "the action must not have run"
        );
    }

    #[test]
    fn an_action_with_the_wrong_csrf_token_is_refused() {
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        let response = route(
            &post(
                "/action",
                "action=pause&minutes=15&csrf=0000000000000000",
                Some(&cookie),
            ),
            peer(),
            &context,
        );
        assert_eq!(response.status, 403);
        assert!(devices::lock_state(&context.state).pause_until.is_none());
    }

    #[test]
    fn a_csrf_token_from_another_session_is_refused() {
        // Tokens are per-session, so one session's token must not authorize
        // another's actions.
        let context = test_context("hunter2");
        let first = sign_in(&context, "hunter2");
        let other_csrf = csrf_for(&context, &first);
        let second = sign_in(&context, "hunter2");
        let response = route(
            &post(
                "/action",
                &format!("action=pause&minutes=15&csrf={other_csrf}"),
                Some(&second),
            ),
            peer(),
            &context,
        );
        assert_eq!(response.status, 403);
    }

    #[test]
    fn a_signed_in_authorized_action_actually_runs() {
        // The happy path, end to end: session + CSRF + a valid action.
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        let csrf = csrf_for(&context, &cookie);
        let response = route(
            &post(
                "/action",
                &format!("action=pause&minutes=15&csrf={csrf}"),
                Some(&cookie),
            ),
            peer(),
            &context,
        );
        assert_eq!(response.status, 303, "redirects back to the panel");
        assert!(
            devices::lock_state(&context.state).pause_until.is_some(),
            "the break should have started"
        );
    }

    #[test]
    fn a_rejected_action_leaves_the_state_alone_and_says_so() {
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        let csrf = csrf_for(&context, &cookie);
        // A blocked device with an address that isn't one.
        let response = route(
            &post(
                "/action",
                &format!("action=block&ip=not-an-ip&csrf={csrf}"),
                Some(&cookie),
            ),
            peer(),
            &context,
        );
        assert_eq!(response.status, 303, "back to the panel with a notice");
        assert!(response.cookies.iter().any(|c| c.contains("notice=")));
    }

    #[test]
    fn signing_out_revokes_the_session() {
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        let response = route(&post("/logout", "", Some(&cookie)), peer(), &context);
        assert_eq!(response.status, 303);

        // The old cookie must no longer work.
        let mut request = get("/");
        request.headers.insert("cookie".to_string(), cookie);
        let response = route(&request, peer(), &context);
        assert!(response.body.contains("name=\"password\""), "back to login");
    }

    #[test]
    fn repeated_bad_passwords_get_throttled() {
        let context = test_context("hunter2");
        let mut saw_lockout = false;
        for _ in 0..(FREE_LOGIN_ATTEMPTS + 3) {
            let response = route(&post("/login", "password=wrong", None), peer(), &context);
            if response.status == 429 {
                saw_lockout = true;
                break;
            }
        }
        assert!(saw_lockout, "brute force must eventually be refused");
    }

    #[test]
    fn a_throttled_address_cannot_then_log_in_correctly_either() {
        // The lockout has to apply before the password is even checked,
        // otherwise the hashing cost is still paid by an attacker.
        let context = test_context("hunter2");
        for _ in 0..(FREE_LOGIN_ATTEMPTS + 2) {
            route(&post("/login", "password=wrong", None), peer(), &context);
        }
        let response = route(&post("/login", "password=hunter2", None), peer(), &context);
        assert_eq!(response.status, 429);
        assert!(context.sessions.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn a_different_address_is_unaffected_by_someone_elses_lockout() {
        let context = test_context("hunter2");
        for _ in 0..(FREE_LOGIN_ATTEMPTS + 2) {
            route(&post("/login", "password=wrong", None), peer(), &context);
        }
        let other: IpAddr = "192.168.1.99".parse().unwrap();
        let response = route(&post("/login", "password=hunter2", None), other, &context);
        assert_eq!(response.status, 303, "a neighbour must not be locked out");
    }

    #[test]
    fn unknown_pages_are_404() {
        let context = test_context("hunter2");
        assert_eq!(route(&get("/etc/passwd"), peer(), &context).status, 404);
        assert_eq!(route(&get("/../config"), peer(), &context).status, 404);
    }

    #[test]
    fn the_static_assets_are_served_without_a_session() {
        // The login page needs its stylesheet before anyone has signed in.
        let context = test_context("hunter2");
        assert_eq!(route(&get("/style.css"), peer(), &context).status, 200);
        assert_eq!(route(&get("/panel.js"), peer(), &context).status, 200);
    }

    #[test]
    fn the_panel_escapes_a_hostile_device_hostname() {
        // A device can call itself anything; it must not become script in the
        // owner's browser.
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        {
            let mut st = devices::lock_state(&context.state);
            st.devices.push("192.168.1.77".to_string());
            st.names.insert(
                "0a:11:22:33:44:55".to_string(),
                "<script>alert(1)</script>".to_string(),
            );
        }
        crate::state::remember_mac(&context.state, "192.168.1.77", "0a:11:22:33:44:55");
        let mut request = get("/");
        request.headers.insert("cookie".to_string(), cookie);
        let response = route(&request, peer(), &context);
        assert!(
            !response.body.contains("<script>alert(1)</script>"),
            "the hostname was injected unescaped"
        );
        assert!(response.body.contains("&lt;script&gt;alert(1)"));
    }

    #[test]
    fn concurrent_bad_logins_are_serialised_not_parallelised() {
        // Each verification is deliberately expensive; the global lock is what
        // stops a burst of attempts from pinning every core.
        assert!(
            HASH_LOCK.try_lock().is_ok(),
            "the hash lock should be free between requests"
        );
    }

    #[test]
    fn the_panel_reports_who_has_been_using_it() {
        // The whole point of the feature: the owner can see the audit trail.
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        let mut request = get("/");
        request.headers.insert("cookie".to_string(), cookie);
        let response = route(&request, peer(), &context);
        assert!(response.body.contains("Who's using Curfew"), "missing the section");
        assert!(response.body.contains("Recent activity"));
        assert!(response.body.contains("this browser"), "own session not marked");
    }

    /// True if the audit log contains an entry of `kind` from `actor`.
    ///
    /// Presence rather than counts: the log is a process-wide singleton and
    /// the tests run in parallel, so each test uses its own address and asks
    /// only whether its own events were recorded.
    fn logged(kind: Kind, actor: &str) -> bool {
        accesslog::with_log(|log| {
            log.all_recent()
                .iter()
                .any(|entry| entry.kind == kind && entry.actor == actor)
        })
    }

    /// Something the log must never contain.
    fn logged_text(needle: &str) -> bool {
        accesslog::with_log(|log| {
            log.all_recent()
                .iter()
                .any(|entry| entry.detail.contains(needle) || entry.actor.contains(needle))
        })
    }

    fn peer_at(address: &str) -> IpAddr {
        address.parse().unwrap()
    }

    #[test]
    fn a_successful_sign_in_is_recorded_with_its_address() {
        let context = test_context("hunter2");
        let who = peer_at("10.9.9.1");
        route(&post("/login", "password=hunter2", None), who, &context);
        assert!(
            logged(Kind::SignedIn, "10.9.9.1"),
            "a sign-in must be recorded, with where it came from"
        );
    }

    #[test]
    fn a_wrong_password_is_recorded_as_an_alert() {
        let context = test_context("hunter2");
        let who = peer_at("10.9.9.2");
        route(&post("/login", "password=guessing", None), who, &context);
        assert!(logged(Kind::SignInFailed, "10.9.9.2"));
        // And it must be flagged, so the owner actually notices.
        let is_alert = accesslog::with_log(|log| {
            log.alerts(50)
                .iter()
                .any(|entry| entry.actor == "10.9.9.2")
        });
        assert!(is_alert, "a failed sign-in should surface as an alert");
    }

    #[test]
    fn the_audit_log_never_contains_the_attempted_password() {
        // This is the property that matters most about an audit log for a
        // login form. The password is not stored, not hashed, not truncated.
        let context = test_context("hunter2");
        let secret = "correct-horse-battery-staple";
        route(
            &post("/login", &format!("password={secret}"), None),
            peer_at("10.9.9.3"),
            &context,
        );
        assert!(
            !logged_text(secret),
            "the attempted password leaked into the audit log"
        );
        // Nor the real one.
        route(
            &post("/login", "password=hunter2", None),
            peer_at("10.9.9.3"),
            &context,
        );
        assert!(!logged_text("hunter2"), "a real password leaked into the log");
    }

    #[test]
    fn an_action_is_recorded_against_the_address_that_made_it() {
        let context = test_context("hunter2");
        let cookie = sign_in(&context, "hunter2");
        let csrf = csrf_for(&context, &cookie);
        route(
            &post(
                "/action",
                &format!("action=pause&minutes=15&csrf={csrf}"),
                Some(&cookie),
            ),
            peer(),
            &context,
        );
        assert!(
            logged(Kind::Action, "192.168.1.50"),
            "a change must be attributable"
        );
    }

    #[test]
    fn signing_out_is_recorded() {
        let context = test_context("hunter2");
        let who = peer_at("10.9.9.4");
        let response = route(&post("/login", "password=hunter2", None), who, &context);
        let cookie = response
            .cookies
            .iter()
            .find(|c| c.starts_with("curfew_session="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        route(&post("/logout", "", Some(&cookie)), who, &context);
        assert!(logged(Kind::SignedOut, "10.9.9.4"));
    }

    #[test]
    fn a_signed_in_owner_can_see_and_end_another_session() {
        // The behaviour the user asked for: spot someone else using it, and
        // stop them.
        let context = test_context("hunter2");
        let mine = sign_in(&context, "hunter2");
        let theirs = sign_in(&context, "hunter2");
        assert_ne!(mine, theirs, "two distinct sessions");

        let ids: Vec<String> = {
            let mut guard = context.sessions.lock().unwrap();
            guard
                .list(Instant::now())
                .into_iter()
                .map(|info| info.id)
                .collect()
        };
        assert_eq!(ids.len(), 2);
        // The other session is the one whose prefix isn't in my cookie.
        let target = ids
            .iter()
            .find(|id| !mine.contains(id.as_str()))
            .expect("the other session")
            .clone();

        let csrf = csrf_for(&context, &mine);
        let response = route(
            &post(
                "/sessions/revoke",
                &format!("id={target}&csrf={csrf}"),
                Some(&mine),
            ),
            peer(),
            &context,
        );
        assert_eq!(response.status, 303);

        let remaining = {
            let mut guard = context.sessions.lock().unwrap();
            guard.list(Instant::now()).len()
        };
        assert_eq!(remaining, 1, "exactly one session was ended");
        assert!(logged(Kind::SessionRevoked, "192.168.1.50"), "audited");
    }

    #[test]
    fn ending_a_session_requires_being_signed_in_yourself() {
        let context = test_context("hunter2");
        let victim = sign_in(&context, "hunter2");
        let id = {
            let mut guard = context.sessions.lock().unwrap();
            guard.list(Instant::now())[0].id.clone()
        };
        let _ = victim;

        let response = route(
            &post("/sessions/revoke", &format!("id={id}"), None),
            peer(),
            &context,
        );
        assert_eq!(response.status, 401, "no session, no revocation");
        let remaining = {
            let mut guard = context.sessions.lock().unwrap();
            guard.list(Instant::now()).len()
        };
        assert_eq!(remaining, 1, "the session survived");
    }

    #[test]
    fn ending_a_session_requires_the_csrf_token() {
        let context = test_context("hunter2");
        let mine = sign_in(&context, "hunter2");
        let _theirs = sign_in(&context, "hunter2");
        let response = route(
            &post("/sessions/revoke", "id=deadbeef", Some(&mine)),
            peer(),
            &context,
        );
        assert_eq!(response.status, 403);
    }

    #[test]
    fn a_too_short_session_id_matches_nothing() {
        // A prefix shorter than the displayed length is refused outright, so a
        // guessed partial id can't end somebody's session.
        let mut sessions = Sessions::default();
        let now = Instant::now();
        sessions.start(now, "10.0.0.1").unwrap();
        assert_eq!(sessions.revoke_prefix("0"), 0);
        assert_eq!(sessions.revoke_prefix(""), 0);
        assert_eq!(sessions.list(now).len(), 1, "nothing was revoked");
    }

    #[test]
    fn one_session_can_sign_out_all_the_others_but_not_itself() {
        let mut sessions = Sessions::default();
        let now = Instant::now();
        let (keep, _) = sessions.start(now, "10.0.0.1").unwrap();
        sessions.start(now, "10.0.0.2").unwrap();
        sessions.start(now, "10.0.0.3").unwrap();
        assert_eq!(sessions.revoke_others(&keep), 2);
        let left = sessions.list(now);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].ip, "10.0.0.1", "the caller keeps their own session");
    }

    #[test]
    fn the_session_list_shows_who_is_connected_and_never_the_token() {
        let mut sessions = Sessions::default();
        let now = Instant::now();
        let (token, _) = sessions.start(now, "192.168.1.77").unwrap();
        let listed = sessions.list(now);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].ip, "192.168.1.77");
        assert_eq!(listed[0].id.len(), SESSION_ID_CHARS);
        // The full token must never be handed out for display.
        assert!(!listed[0].id.eq(&token));
        assert!(token.starts_with(&listed[0].id));
    }

    #[test]
    fn session_ages_are_reported() {
        let mut sessions = Sessions::default();
        let start = Instant::now();
        sessions.start(start, "10.0.0.1").unwrap();
        let later = start + Duration::from_secs(125);
        let listed = sessions.list(later);
        assert_eq!(listed[0].age_secs, 125);
        assert_eq!(listed[0].idle_secs, 125);
    }

    #[test]
    fn reads_the_port_from_a_web_address() {
        assert_eq!(port_of("0.0.0.0:8787"), 8787);
        assert_eq!(port_of("127.0.0.1:9000"), 9000);
        // No port named: the default.
        assert_eq!(port_of("0.0.0.0"), DEFAULT_PORT);
        assert_eq!(port_of("localhost"), DEFAULT_PORT);
        // Nonsense port: fall back rather than panic.
        assert_eq!(port_of("host:not-a-port"), DEFAULT_PORT);
    }

    #[test]
    fn serves_a_real_request_over_a_socket() {
        // Exercises the parts `route` tests can't reach: the accept loop's
        // connection setup and the actual HTTP serialisation on the wire.
        use std::io::Read;

        let context = test_context("hunter2");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let _ = handle_connection(stream, context);
        });

        let mut client = TcpStream::connect(address).expect("connect");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        // The server closes the connection, so this reads to EOF.
        let mut raw = String::new();
        client.read_to_string(&mut raw).unwrap();
        server.join().unwrap();

        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "raw was: {raw:.80}");
        assert!(raw.contains("\r\nContent-Length: "));
        assert!(raw.contains("\r\nConnection: close\r\n"));
        // Each response must carry its own body, delimited by a blank line.
        let (headers, body) = raw.split_once("\r\n\r\n").expect("headers then body");
        let declared: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|value| value.trim().parse().ok())
            .expect("a content length");
        assert_eq!(declared, body.len(), "Content-Length must match the body");
    }

    #[test]
    fn a_malformed_request_gets_a_400_over_a_socket() {
        use std::io::Read;

        let context = test_context("hunter2");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let _ = handle_connection(stream, context);
        });

        let mut client = TcpStream::connect(address).expect("connect");
        client.write_all(b"GARBAGE\r\n\r\n").unwrap();
        let mut raw = String::new();
        client.read_to_string(&mut raw).unwrap();
        server.join().unwrap();

        assert!(raw.starts_with("HTTP/1.1 400 "), "raw was: {raw:.80}");
    }

    #[test]
    fn the_server_entry_point_serves_and_then_shuts_down() {
        // Without this, everything above could pass while `serve` itself was
        // broken, and the whole feature would be dead on arrival.
        use std::io::Read;

        // Pick a free port by binding and releasing it. There's a small race
        // with another process taking it, but nothing else is listening here.
        let port = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("probe");
            probe.local_addr().unwrap().port()
        };

        let context = test_context("hunter2");
        let server_context = Arc::clone(&context);
        let server = std::thread::spawn(move || {
            serve(&format!("127.0.0.1:{port}"), server_context).expect("serve");
        });

        // Give the listener a moment to come up.
        let mut connected = None;
        for _ in 0..100 {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let mut client = connected.expect("the server should accept connections");
        client
            .write_all(b"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut raw = String::new();
        client.read_to_string(&mut raw).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200 OK"), "raw was: {raw:.80}");
        assert!(raw.contains("name=\"password\""));

        // Asking to stop must end the accept loop rather than hang.
        *context.shutdown.lock().unwrap() = true;
        // Nudge it so a blocked `accept` returns.
        let _ = TcpStream::connect(("127.0.0.1", port));

        let deadline = Instant::now() + Duration::from_secs(5);
        while !server.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(server.is_finished(), "the server should have stopped");
        server.join().unwrap();
    }
}

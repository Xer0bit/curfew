//! Identifying devices: normalising MAC addresses, looking up the hardware
//! vendor, and — importantly — detecting the MACs that *can't* be used for
//! identification at all.
//!
//! # The randomised-MAC problem
//!
//! Since iOS 14 and Android 10, phones and tablets use a **private Wi-Fi
//! address** by default: a random MAC that the device rotates, sometimes per
//! network and sometimes periodically. Any rule keyed to such a MAC silently
//! stops matching the next time the device reconnects.
//!
//! A randomised MAC is always *locally administered* — bit 1 of the first
//! octet is set — so it's detectable. [`is_randomised`] does that, and the UI
//! flags those devices rather than pretending their settings will stick.
//! The fix is on the device: turn off "Private Wi-Fi Address" for your home
//! network (iOS/Android both allow it per-network), after which the hardware
//! MAC is used and rules behave.
//!
//! # Vendor lookup
//!
//! No vendor table is vendored into the binary. One is already on disk on any
//! machine that has Curfew's prerequisites: `nmap` ships
//! `nmap-mac-prefixes`, and many distros also install the IEEE `oui.txt`.
//! Both formats are parsed; an optional hand-written override file wins over
//! either.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Where to look for a MAC-vendor database, in order. The first readable file
/// wins. The override path lets a user supply their own without root access
/// to a package directory.
fn candidate_paths() -> Vec<std::path::PathBuf> {
    let mut paths = vec![std::path::Path::new(crate::paths::CONFIG_DIR).join("oui.txt")];
    #[cfg(unix)]
    {
        paths.push("/usr/share/nmap/nmap-mac-prefixes".into());
        paths.push("/usr/local/share/nmap/nmap-mac-prefixes".into());
        paths.push("/opt/homebrew/share/nmap/nmap-mac-prefixes".into());
        paths.push("/usr/share/ieee-data/oui.txt".into());
        paths.push("/var/lib/ieee-data/oui.txt".into());
    }
    #[cfg(windows)]
    {
        paths.push(r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes".into());
        paths.push(r"C:\Program Files\Nmap\nmap-mac-prefixes".into());
    }
    paths
}

/// The loaded vendor table: 6 uppercase hex digits -> vendor name.
static VENDORS: OnceLock<HashMap<String, String>> = OnceLock::new();

fn vendors() -> &'static HashMap<String, String> {
    VENDORS.get_or_init(|| {
        for path in candidate_paths() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let table = parse_vendor_file(&content);
                if !table.is_empty() {
                    return table;
                }
            }
        }
        HashMap::new()
    })
}

/// Parses either vendor-file format.
///
/// `nmap-mac-prefixes`:  `001451 Apple`
/// IEEE `oui.txt`:       `10-E9-92   (hex)    INGRAM MICRO SERVICES`
///
/// Lines beginning with `#` are comments in both. Unrecognisable lines are
/// skipped rather than aborting, so a partially-downloaded or extended file
/// still yields a usable table.
pub fn parse_vendor_file(content: &str) -> HashMap<String, String> {
    let mut table = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (prefix, rest) = match line.split_once(char::is_whitespace) {
            Some(parts) => parts,
            None => continue,
        };

        // IEEE format separates the prefix with dashes and follows it with a
        // "(hex)" marker; nmap's is a bare 6-digit prefix.
        let normalized: String = prefix
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_uppercase();
        if normalized.len() != 6 {
            continue;
        }

        let rest = rest.trim();
        let rest = rest.strip_prefix("(hex)").unwrap_or(rest).trim();
        // IEEE entries carry a "(base 16)" suffix on some lines.
        let rest = rest.strip_suffix("(base 16)").unwrap_or(rest).trim();
        if rest.is_empty() {
            continue;
        }

        table.entry(normalized).or_insert_with(|| rest.to_string());
    }
    table
}

/// Normalises a MAC address to lowercase `aa:bb:cc:dd:ee:ff`.
///
/// Accepts the separator styles different tools emit: `arp -a` on Windows uses
/// dashes, and some systems print no separators at all.
pub fn normalize_mac(input: &str) -> Option<String> {
    let hex: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase();
    if hex.len() != 12 {
        return None;
    }
    Some(
        (0..6)
            .map(|i| &hex[i * 2..i * 2 + 2])
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// The 6 uppercase hex digits a vendor lookup is keyed on.
fn oui_key(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    (hex.len() == 12).then(|| hex[..6].to_string())
}

/// The hardware vendor for `mac`, if the vendor table knows it.
pub fn vendor(mac: &str) -> Option<String> {
    let key = oui_key(mac)?;
    vendors().get(&key).cloned()
}

/// True if a vendor table was found on this machine, so the UI can explain
/// *why* vendors are missing rather than just showing blanks.
pub fn vendor_table_available() -> bool {
    !vendors().is_empty()
}

/// A one-line explanation when no vendor table could be found, for the UI.
pub fn missing_table_hint() -> Option<&'static str> {
    if vendor_table_available() {
        None
    } else {
        Some(
            "No device-maker list found. It ships with nmap; without it, devices \
             are shown by name or address only.",
        )
    }
}

/// True if `mac` is locally administered, which in practice means it is a
/// randomised "private" address rather than the hardware address burned into
/// the device.
///
/// Bit 1 of the first octet is the locally-administered flag; bit 0 is the
/// multicast flag. A locally-administered, unicast address is what every
/// privacy implementation generates.
pub fn is_randomised(mac: &str) -> bool {
    let Some(normalized) = normalize_mac(mac) else {
        return false;
    };
    let Some(first) = normalized.split(':').next() else {
        return false;
    };
    match u8::from_str_radix(first, 16) {
        Ok(octet) => octet & 0b10 != 0,
        Err(_) => false,
    }
}

/// A rough guess at what a device is, from its hostname and vendor.
///
/// Deliberately coarse and clearly presented as a guess: hostnames are
/// self-reported and often absent. It exists to make a device list readable
/// ("Kid's iPad") rather than to be authoritative.
pub fn guess_kind(hostname: Option<&str>, vendor_name: Option<&str>) -> Option<&'static str> {
    let host = hostname.unwrap_or_default().to_lowercase();
    let vendor_lower = vendor_name.unwrap_or_default().to_lowercase();

    // Hostnames first — when present they're far more specific than a vendor.
    const HOST_HINTS: &[(&str, &str)] = &[
        ("iphone", "phone"),
        ("ipad", "tablet"),
        ("ipod", "phone"),
        ("macbook", "laptop"),
        ("imac", "desktop"),
        ("mac-mini", "desktop"),
        ("apple-tv", "TV"),
        ("appletv", "TV"),
        ("android", "phone"),
        ("pixel", "phone"),
        ("galaxy", "phone"),
        ("sm-t", "tablet"),
        ("tab", "tablet"),
        ("laptop", "laptop"),
        ("desktop", "desktop"),
        ("pc-", "desktop"),
        ("chromecast", "TV"),
        ("firestick", "TV"),
        ("fire-tv", "TV"),
        ("bravia", "TV"),
        ("webos", "TV"),
        ("tizen", "TV"),
        ("roku", "TV"),
        // Least specific, so it comes last: plenty of hostnames mention "tv"
        // ("livingroom-tv", "tvbox") but the more precise hints above should
        // win when they apply.
        ("tv", "TV"),
        ("switch", "console"),
        ("playstation", "console"),
        ("xbox", "console"),
        ("printer", "printer"),
        ("hp-", "printer"),
        ("epson", "printer"),
        ("brother", "printer"),
        ("canon", "printer"),
        ("echo", "speaker"),
        ("alexa", "speaker"),
        ("homepod", "speaker"),
        ("nest", "smart home"),
        ("camera", "camera"),
        ("doorbell", "camera"),
        ("raspberrypi", "computer"),
        ("raspberry", "computer"),
        ("router", "router"),
    ];
    for (needle, kind) in HOST_HINTS {
        if host.contains(needle) {
            return Some(kind);
        }
    }

    const VENDOR_HINTS: &[(&str, &str)] = &[
        ("apple", "Apple device"),
        ("samsung", "Samsung device"),
        ("xiaomi", "Xiaomi device"),
        ("oneplus", "phone"),
        ("huawei", "phone"),
        ("oppo", "phone"),
        ("vivo", "phone"),
        ("google", "Google device"),
        ("amazon", "Amazon device"),
        ("sonos", "speaker"),
        ("roku", "TV"),
        ("lg electronics", "TV"),
        ("sony", "Sony device"),
        ("philips", "smart home"),
        ("espressif", "smart home"),
        ("tuya", "smart home"),
        ("shelly", "smart home"),
        ("tp-link", "network gear"),
        ("netgear", "network gear"),
        ("ubiquiti", "network gear"),
        ("intel", "computer"),
        ("dell", "computer"),
        ("hewlett", "computer"),
        ("lenovo", "computer"),
        ("asustek", "computer"),
        ("micro-star", "computer"),
        ("gigabyte", "computer"),
        ("raspberry", "computer"),
        ("espressif", "smart home"),
        ("brother", "printer"),
        ("seiko epson", "printer"),
        ("canon", "printer"),
        ("nintendo", "console"),
        ("microsoft", "Microsoft device"),
    ];
    for (needle, kind) in VENDOR_HINTS {
        if vendor_lower.contains(needle) {
            return Some(kind);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_every_separator_style() {
        let expected = "aa:bb:cc:dd:ee:ff".to_string();
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:ff"), Some(expected.clone()));
        assert_eq!(normalize_mac("AA:BB:CC:DD:EE:FF"), Some(expected.clone()));
        assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), Some(expected.clone()));
        assert_eq!(normalize_mac("aabbccddeeff"), Some(expected.clone()));
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF"), Some(expected.clone()));
    }

    #[test]
    fn rejects_things_that_are_not_macs() {
        for bad in ["", "unknown", "aa:bb:cc", "not a mac address", "aabbccddeeff00"] {
            assert_eq!(normalize_mac(bad), None, "should reject {bad:?}");
        }
    }

    #[test]
    fn parses_the_nmap_vendor_format() {
        let table = parse_vendor_file(
            "# a comment\n\
             001451 Apple\n\
             3C22FB Apple\n\
             F0EF86 Google\n",
        );
        assert_eq!(table.get("001451").map(String::as_str), Some("Apple"));
        assert_eq!(table.get("F0EF86").map(String::as_str), Some("Google"));
        assert_eq!(table.len(), 3, "comments must be ignored");
    }

    #[test]
    fn parses_the_ieee_vendor_format() {
        let table = parse_vendor_file(
            "10-E9-92   (hex)                INGRAM MICRO SERVICES\n\
             78-F2-76   (hex)                Cyklop Fastjet Technologies (Shanghai) Inc.\n\
             00-00-00   (hex)                XEROX CORPORATION\n",
        );
        assert_eq!(
            table.get("10E992").map(String::as_str),
            Some("INGRAM MICRO SERVICES")
        );
        assert_eq!(
            table.get("78F276").map(String::as_str),
            Some("Cyklop Fastjet Technologies (Shanghai) Inc.")
        );
    }

    #[test]
    fn skips_lines_it_cannot_understand() {
        let table = parse_vendor_file(
            "\n\
             not a vendor line\n\
             00\n\
             ZZZZZZ Bad\n\
             001451 Apple\n",
        );
        assert_eq!(table.len(), 1, "only the valid line should survive");
    }

    #[test]
    fn randomised_macs_are_detected() {
        // The locally-administered bit is 0x02 of the first octet. These are
        // the shapes real phones produce.
        for randomised in [
            "02:11:22:33:44:55",
            "06:11:22:33:44:55",
            "0a:11:22:33:44:55",
            "0e:11:22:33:44:55",
            "1a:2b:3c:4d:5e:6f",
            "ba:11:22:33:44:55",
        ] {
            assert!(
                is_randomised(randomised),
                "{randomised} should be seen as randomised"
            );
        }
    }

    #[test]
    fn hardware_macs_are_not_flagged_as_randomised() {
        for real in [
            "00:14:51:11:22:33",
            "3c:22:fb:11:22:33",
            "f0:ef:86:11:22:33",
            "a4:83:e7:11:22:33",
            "cc:2d:1b:11:22:33",
        ] {
            assert!(
                !is_randomised(real),
                "{real} is a real vendor prefix and must not be flagged"
            );
        }
    }

    #[test]
    fn a_multicast_address_is_not_mistaken_for_a_privacy_address() {
        // 01:00:5e is multicast (bit 0 set, bit 1 clear) — a classic bug is
        // testing the wrong bit.
        assert!(!is_randomised("01:00:5e:00:00:01"));
    }

    #[test]
    fn unparseable_macs_are_not_claimed_to_be_randomised() {
        assert!(!is_randomised("unknown"));
        assert!(!is_randomised(""));
    }

    #[test]
    fn guesses_device_kind_from_a_hostname() {
        assert_eq!(guess_kind(Some("Kids-iPad"), None), Some("tablet"));
        assert_eq!(guess_kind(Some("iPhone-de-Tim"), None), Some("phone"));
        assert_eq!(guess_kind(Some("livingroom-tv"), None), Some("TV"));
        assert_eq!(guess_kind(Some("DESKTOP-4F2K1"), None), Some("desktop"));
        assert_eq!(guess_kind(Some("raspberrypi"), None), Some("computer"));
        assert_eq!(guess_kind(Some("HP-Print-42"), None), Some("printer"));
    }

    #[test]
    fn guesses_device_kind_from_a_vendor_when_there_is_no_hostname() {
        assert_eq!(guess_kind(None, Some("Apple")), Some("Apple device"));
        assert_eq!(guess_kind(None, Some("Sonos Inc")), Some("speaker"));
        assert_eq!(guess_kind(None, Some("Nintendo Co.,Ltd")), Some("console"));
    }

    #[test]
    fn a_hostname_beats_the_vendor() {
        // "Apple" alone can't tell a phone from a laptop; the hostname can.
        assert_eq!(guess_kind(Some("macbook-pro"), Some("Apple")), Some("laptop"));
        assert_eq!(guess_kind(Some("iPhone"), Some("Apple")), Some("phone"));
    }

    #[test]
    fn makes_no_claim_when_it_has_nothing_to_go_on() {
        assert_eq!(guess_kind(None, None), None);
        assert_eq!(guess_kind(Some("unknown"), Some("Some Obscure Ltd")), None);
    }

    #[test]
    fn vendor_lookup_works_against_a_hand_built_table() {
        // Exercises the same lookup path as the real table without depending
        // on what's installed on the test machine.
        let table = parse_vendor_file("001451 Apple\n");
        assert_eq!(table.get("001451").map(String::as_str), Some("Apple"));
        assert_eq!(oui_key("00:14:51:aa:bb:cc").unwrap(), "001451");
    }
}

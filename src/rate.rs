//! The throttle speeds Curfew offers, in one place.
//!
//! Before this module existed the rate list was duplicated in three spots
//! (`main::ask_rate_friendly`, `ui::speed_menu`, `ui::friendly_rate`) and they
//! had drifted: first-run setup offered two speeds while the menu offered
//! three, and the dashboard had no label at all for `1mbit`, so a user who
//! chose "only a little slow" still saw the same text as the harshest setting.
//! Everything now reads from [`CHOICES`].

/// One selectable speed. `key` is the value persisted to disk and handed to
/// `tc`/`dnctl`; `friendly` is the short dashboard phrase; `menu` is the
/// longer first-run/menu description.
pub struct RateChoice {
    pub key: &'static str,
    pub friendly: &'static str,
    pub menu: &'static str,
}

/// Every speed the user can pick, gentlest last.
pub const CHOICES: &[RateChoice] = &[
    RateChoice {
        key: "10kbit",
        friendly: "slowed right down",
        menu: "Barely works — best for getting kids off screens",
    },
    RateChoice {
        key: "256kbit",
        friendly: "slowed down",
        menu: "Slow, but still usable",
    },
    RateChoice {
        key: "1mbit",
        friendly: "only a little slow",
        menu: "Only a little slow",
    },
    RateChoice {
        key: "5mbit",
        friendly: "nearly full speed",
        menu: "Gentle — barely noticeable",
    },
];

/// The default when the user just presses Enter.
pub const DEFAULT_KEY: &str = "10kbit";

/// Options shown during first-run setup. Deliberately shorter than
/// [`CHOICES`]: a brand-new user should face one obvious recommendation, not
/// a menu — the rest stay reachable later via option 6.
pub const SETUP_CHOICES: &[&str] = &["10kbit", "256kbit"];

/// Short dashboard phrase for `rate`, e.g. "slowed right down".
pub fn friendly(rate: &str) -> &'static str {
    CHOICES
        .iter()
        .find(|c| c.key == rate)
        .map(|c| c.friendly)
        .unwrap_or("slowed down")
}

/// Longer menu description for `rate`.
pub fn menu_label(rate: &str) -> &'static str {
    CHOICES
        .iter()
        .find(|c| c.key == rate)
        .map(|c| c.menu)
        .unwrap_or("Slowed down")
}

/// True if `rate` is one of the throttle speeds — i.e. a valid answer for
/// "how slow should everyone be", as opposed to the per-device "no throttle"
/// value, which makes no sense as a household default.
pub fn is_throttle_rate(rate: &str) -> bool {
    CHOICES.iter().any(|c| c.key == rate)
}

/// Parses a throttle rate into bits per second, accepting both Curfew's own
/// form (`"10kbit"`) and `dnctl`'s (`"10Kbit/s"`). Returns `None` for
/// anything it can't understand rather than guessing.
///
/// Only the macOS and Windows backends need the numeric value — Linux hands
/// the string straight to `tc` — so this is compiled only where it's used.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub fn parse_bps(rate: &str) -> Option<u64> {
    let trimmed = rate.trim().to_lowercase();
    let trimmed = trimmed.trim_end_matches("/s");

    let split_at = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, unit) = trimmed.split_at(split_at);
    let value: u64 = digits.parse().ok()?;

    let per_second = match unit.trim() {
        "bit" | "bps" | "" => 1,
        "kbit" | "kbps" | "kb" | "k" => 1_000,
        "mbit" | "mbps" | "mb" | "m" => 1_000_000,
        "gbit" | "gbps" | "gb" | "g" => 1_000_000_000,
        _ => return None,
    };
    value.checked_mul(per_second)
}

/// Formats a bit rate back into `dnctl`'s expected `"<n>Kbit/s"` style.
#[cfg(any(target_os = "macos", test))]
pub fn to_dnctl(rate: &str) -> String {
    let bps = match parse_bps(rate) {
        Some(b) => b,
        // Passing an unrecognised string through is better than silently
        // substituting a different speed; dnctl will reject it loudly.
        None => return rate.to_string(),
    };
    if bps >= 1_000_000 && bps % 1_000_000 == 0 {
        format!("{}Mbit/s", bps / 1_000_000)
    } else if bps >= 1_000 && bps % 1_000 == 0 {
        format!("{}Kbit/s", bps / 1_000)
    } else {
        format!("{bps}bit/s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_own_format() {
        assert_eq!(parse_bps("10kbit"), Some(10_000));
        assert_eq!(parse_bps("256kbit"), Some(256_000));
        assert_eq!(parse_bps("1mbit"), Some(1_000_000));
        assert_eq!(parse_bps("5mbit"), Some(5_000_000));
    }

    #[test]
    fn parses_dnctl_format() {
        assert_eq!(parse_bps("10Kbit/s"), Some(10_000));
        assert_eq!(parse_bps("256Kbit/s"), Some(256_000));
        assert_eq!(parse_bps("1Mbit/s"), Some(1_000_000));
    }

    #[test]
    fn rejects_garbage_instead_of_guessing() {
        assert_eq!(parse_bps(""), None);
        assert_eq!(parse_bps("kbit"), None);
        assert_eq!(parse_bps("fast"), None);
        assert_eq!(parse_bps("10furlongs"), None);
    }

    #[test]
    fn every_choice_has_a_distinct_friendly_label() {
        // The original bug: two different speeds rendering identically.
        let mut seen = std::collections::HashSet::new();
        for choice in CHOICES {
            assert!(
                seen.insert(choice.friendly),
                "duplicate dashboard label {:?}",
                choice.friendly
            );
        }
    }

    #[test]
    fn setup_choices_are_real_rates() {
        for key in SETUP_CHOICES {
            assert!(is_throttle_rate(key), "setup offers unknown rate {key}");
        }
    }

    #[test]
    fn the_no_throttle_value_is_not_a_valid_household_default() {
        // Nothing called "full" is offered as a household rate; full speed is
        // represented by a device being absent from the plan entirely.
        assert!(!is_throttle_rate("full"));
    }

    #[test]
    fn default_is_a_real_rate() {
        assert!(is_throttle_rate(DEFAULT_KEY));
    }

    #[test]
    fn round_trips_through_dnctl_format() {
        for choice in CHOICES {
            let converted = to_dnctl(choice.key);
            assert_eq!(
                parse_bps(&converted),
                parse_bps(choice.key),
                "{} lost precision: {converted}",
                choice.key
            );
        }
    }

    #[test]
    fn friendly_falls_back_for_unknown_rate() {
        assert_eq!(friendly("nonsense"), "slowed down");
        assert_eq!(menu_label("nonsense"), "Slowed down");
    }
}

//! Derive an Exchange/Windows timezone identifier from the operating system.

use windows_timezones::WindowsTimezone;

const FALLBACK_TIMEZONE: &str = "UTC";

pub fn system_exchange_timezone() -> String {
    iana_time_zone::get_timezone()
        .ok()
        .and_then(|iana| exchange_timezone_for_iana(&iana))
        .unwrap_or_else(|| FALLBACK_TIMEZONE.to_string())
}

fn exchange_timezone_for_iana(iana: &str) -> Option<String> {
    let timezone = iana.parse::<chrono_tz::Tz>().ok()?;
    WindowsTimezone::try_from(timezone)
        .ok()
        .map(|windows| windows.name().to_string())
}

#[cfg(test)]
mod tests {
    use super::{exchange_timezone_for_iana, system_exchange_timezone};

    #[test]
    fn maps_iana_timezone_to_exchange_identifier() {
        assert_eq!(
            exchange_timezone_for_iana("America/New_York").as_deref(),
            Some("Eastern Standard Time")
        );
        assert_eq!(
            exchange_timezone_for_iana("Europe/Berlin").as_deref(),
            Some("W. Europe Standard Time")
        );
        assert!(exchange_timezone_for_iana("Invalid/Timezone").is_none());
    }

    #[test]
    fn system_default_is_nonempty() {
        assert!(!system_exchange_timezone().is_empty());
    }
}

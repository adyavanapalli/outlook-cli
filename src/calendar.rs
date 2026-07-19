//! `outlook calendar` commands and OWA summary normalization.

use crate::auth;
use crate::output;
use crate::owa::{self, OwaError, Week, WeekRange};
use crate::session::Store;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
pub struct CalendarList {
    pub week: Week,
    pub range: WeekRange,
    pub count: usize,
    pub events: Vec<CalendarEvent>,
}

/// Stable JSON projection of the independent boolean flags returned by OWA.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
pub struct CalendarEvent {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    pub subject: String,
    pub start: String,
    pub end: String,
    pub all_day: bool,
    pub cancelled: bool,
    pub meeting: bool,
    pub recurring: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar_item_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_busy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organizer: Option<Organizer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub teams_meeting: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
}

#[derive(Serialize)]
pub struct Organizer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

pub fn list(store: &Store, week: Week, raw: bool) -> anyhow::Result<()> {
    let _session_lock = store.acquire_session_lock()?;
    let mut session = store.load()?;
    auth::ensure_access(store, &mut session, false)?;
    auth::ensure_bootstrap(store, &mut session)?;
    store.save(&session)?;
    let range = WeekRange::current(week);
    let mut response = owa::get_calendar_view(&session.auth, &range, &session.config.timezone);
    if matches!(response, Err(OwaError::Unauthorized)) {
        if let Some(token) = session.auth.access_token.as_mut() {
            token.expires_at = 0;
        }
        auth::ensure_access(store, &mut session, false)?;
        store.save(&session)?;
        response = owa::get_calendar_view(&session.auth, &range, &session.config.timezone);
    }
    let response = response.map_err(anyhow::Error::new)?;
    if raw {
        return output::json(&response);
    }
    let list = normalize(week, range, &response)?;
    output::json(&list)
}

fn normalize(week: Week, range: WeekRange, response: &Value) -> anyhow::Result<CalendarList> {
    let items = response
        .get("Body")
        .and_then(|body| body.get("Items"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("OWA calendar response has no Body.Items array"))?;
    let mut events: Vec<CalendarEvent> = items.iter().filter_map(normalize_event).collect();
    events.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.subject.cmp(&right.subject))
    });
    Ok(CalendarList {
        week,
        range,
        count: events.len(),
        events,
    })
}

fn normalize_event(item: &Value) -> Option<CalendarEvent> {
    let id = string_at(item, "/ItemId/Id")?;
    let subject = item
        .get("Subject")
        .and_then(Value::as_str)
        .unwrap_or("(no subject)")
        .to_string();
    let start = item.get("Start")?.as_str()?.to_string();
    let end = item.get("End")?.as_str()?.to_string();
    let organizer_mailbox = item.get("Organizer").and_then(|value| value.get("Mailbox"));
    let organizer = organizer_mailbox.map(|mailbox| Organizer {
        name: optional_string(mailbox, "Name"),
        email: optional_string(mailbox, "SmtpEmailAddress")
            .or_else(|| optional_string(mailbox, "EmailAddress")),
    });
    let location = item
        .get("Location")
        .and_then(|value| optional_string(value, "DisplayName"));
    let teams_meeting = location
        .as_deref()
        .is_some_and(|value| value.to_ascii_lowercase().contains("teams"));
    let categories = item
        .get("Categories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect();
    Some(CalendarEvent {
        id,
        change_key: string_at(item, "/ItemId/ChangeKey"),
        uid: optional_string(item, "UID"),
        subject,
        start,
        end,
        all_day: boolean(item, "IsAllDayEvent"),
        cancelled: boolean(item, "IsCancelled"),
        meeting: boolean(item, "IsMeeting"),
        recurring: boolean(item, "IsRecurring"),
        calendar_item_type: optional_string(item, "CalendarItemType"),
        response_type: optional_string(item, "ResponseType"),
        free_busy: optional_string(item, "FreeBusyType"),
        organizer,
        location,
        teams_meeting,
        categories,
    })
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn string_at(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn boolean(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::normalize;
    use crate::owa::{Week, WeekRange};
    use chrono::NaiveDate;
    use serde_json::json;

    #[test]
    fn normalizes_and_sorts_calendar_items() {
        let response = json!({
            "Body": { "Items": [
                {
                    "ItemId": {"Id": "later", "ChangeKey": "c"},
                    "UID": "u", "Subject": "Later",
                    "Start": "2026-07-14T10:00:00-04:00", "End": "2026-07-14T11:00:00-04:00",
                    "IsMeeting": true, "IsRecurring": true,
                    "Location": {"DisplayName": "Microsoft Teams Meeting"},
                    "Organizer": {"Mailbox": {"Name": "A", "SmtpEmailAddress": "a@example.com"}},
                    "Categories": ["Blue"]
                },
                {
                    "ItemId": {"Id": "earlier"}, "Subject": "Earlier",
                    "Start": "2026-07-13T09:00:00-04:00", "End": "2026-07-13T09:30:00-04:00"
                }
            ]}
        });
        let range = WeekRange {
            start: NaiveDate::from_ymd_opt(2026, 7, 12).unwrap(),
            end_exclusive: NaiveDate::from_ymd_opt(2026, 7, 19).unwrap(),
        };
        let list = normalize(Week::Current, range, &response).unwrap();
        assert_eq!(list.count, 2);
        assert_eq!(list.events[0].id, "earlier");
        assert_eq!(list.events[1].id, "later");
        assert!(list.events[1].teams_meeting);
        assert_eq!(
            list.events[1].organizer.as_ref().unwrap().email.as_deref(),
            Some("a@example.com")
        );
    }
}

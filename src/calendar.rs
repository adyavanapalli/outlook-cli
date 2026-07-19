//! `outlook calendar` commands and OWA summary normalization.

use crate::auth;
use crate::output;
use crate::owa::{self, OwaError, Week, WeekRange};
use crate::session::{AuthState, SessionFile, Store};
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

/// Stable JSON projection of independent event and reminder flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
pub struct CalendarEventDetails {
    #[serde(flatten)]
    pub event: CalendarEvent,
    pub online_meeting: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_meeting_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_meeting_join_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_meeting_chat_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<CalendarBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_attendees: Vec<CalendarAttendee>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub optional_attendees: Vec<CalendarAttendee>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<CalendarAttendee>,
    pub response_requested: bool,
    pub allow_new_time_proposal: bool,
    pub reminder_set: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reminder_minutes_before_start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series_master_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub importance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_zone: Option<String>,
}

#[derive(Serialize)]
pub struct CalendarBody {
    pub content_type: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct CalendarAttendee {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attendance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
}

pub fn list(store: &Store, week: Week, raw: bool) -> anyhow::Result<()> {
    let (_session_lock, mut session) = authenticated_session(store, true)?;
    let range = WeekRange::current(week);
    let time_zone = session.config.timezone.clone();
    let response = request_with_retry(store, &mut session, |auth| {
        owa::get_calendar_view(auth, &range, &time_zone)
    })?;
    if raw {
        return output::json(&response);
    }
    output::json(&normalize(week, range, &response)?)
}

pub fn get(store: &Store, id: &str, raw: bool) -> anyhow::Result<()> {
    let id = validate_event_id(id)?;
    let (_session_lock, mut session) = authenticated_session(store, false)?;
    let time_zone = session.config.timezone.clone();
    let response = request_with_retry(store, &mut session, |auth| {
        owa::get_calendar_event(auth, id, &time_zone)
    })?;
    if raw {
        return output::json(&response);
    }
    output::json(&normalize_details(&response)?)
}

fn authenticated_session(
    store: &Store,
    bootstrap: bool,
) -> anyhow::Result<(std::fs::File, SessionFile)> {
    let session_lock = store.acquire_session_lock()?;
    let mut session = store.load()?;
    auth::ensure_access(store, &mut session, false)?;
    if bootstrap {
        auth::ensure_bootstrap(store, &mut session)?;
    }
    store.save(&session)?;
    Ok((session_lock, session))
}

fn request_with_retry<T, F>(
    store: &Store,
    session: &mut SessionFile,
    mut operation: F,
) -> anyhow::Result<T>
where
    F: FnMut(&AuthState) -> Result<T, OwaError>,
{
    let mut result = operation(&session.auth);
    if matches!(result, Err(OwaError::Unauthorized)) {
        if let Some(token) = session.auth.access_token.as_mut() {
            token.expires_at = 0;
        }
        store.save(session)?;
        auth::ensure_access(store, session, false)?;
        store.save(session)?;
        result = operation(&session.auth);
        if matches!(result, Err(OwaError::Unauthorized)) {
            session.auth.access_token = None;
            store.save(session)?;
        }
    }
    result.map_err(anyhow::Error::new)
}

fn validate_event_id(id: &str) -> anyhow::Result<&str> {
    let id = id.trim();
    if id.is_empty() {
        anyhow::bail!("calendar event ID cannot be empty");
    }
    if id.chars().any(char::is_control) {
        anyhow::bail!("calendar event ID contains unsupported control characters");
    }
    Ok(id)
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

fn normalize_details(response: &Value) -> anyhow::Result<CalendarEventDetails> {
    let message = response
        .pointer("/Body/ResponseMessages/Items/0")
        .ok_or_else(|| anyhow::anyhow!("OWA GetCalendarEvent response has no response message"))?;
    let response_class = message
        .get("ResponseClass")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let response_code = message
        .get("ResponseCode")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if response_class != "Success" || response_code != "NoError" {
        anyhow::bail!("OWA GetCalendarEvent failed: class={response_class}, code={response_code}");
    }
    let item = message
        .get("Items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| anyhow::anyhow!("OWA GetCalendarEvent response has no event"))?;
    let mut event = normalize_event(item)
        .ok_or_else(|| anyhow::anyhow!("OWA GetCalendarEvent response has an invalid event"))?;
    let online_meeting_provider = optional_string(item, "OnlineMeetingProvider");
    let online_meeting_join_url = optional_string(item, "OnlineMeetingJoinUrl");
    event.teams_meeting |= online_meeting_provider
        .as_deref()
        .is_some_and(|provider| provider.to_ascii_lowercase().contains("teams"))
        || online_meeting_join_url
            .as_deref()
            .is_some_and(is_teams_join_url);
    let body = item.get("Body").map(|body| CalendarBody {
        content_type: optional_string(body, "BodyType").unwrap_or_else(|| "unknown".to_string()),
        content: optional_string(body, "Value").unwrap_or_default(),
    });
    Ok(CalendarEventDetails {
        event,
        online_meeting: boolean(item, "IsOnlineMeeting"),
        online_meeting_provider,
        online_meeting_join_url,
        online_meeting_chat_id: optional_string(item, "OnlineMeetingChatId"),
        body,
        preview: optional_string(item, "Preview"),
        required_attendees: normalize_attendees(item, "RequiredAttendees"),
        optional_attendees: normalize_attendees(item, "OptionalAttendees"),
        resources: normalize_attendees(item, "Resources"),
        response_requested: boolean(item, "IsResponseRequested"),
        allow_new_time_proposal: boolean(item, "AllowNewTimeProposal"),
        reminder_set: boolean(item, "ReminderIsSet"),
        reminder_minutes_before_start: unsigned(item, "ReminderMinutesBeforeStart"),
        series_id: optional_string(item, "SeriesId"),
        series_master_id: string_at(item, "/SeriesMasterItemId/Id"),
        conversation_id: string_at(item, "/ConversationId/Id"),
        item_class: optional_string(item, "ItemClass"),
        importance: optional_string(item, "Importance"),
        sensitivity: optional_string(item, "Sensitivity"),
        created_at: optional_string(item, "DateTimeCreated"),
        modified_at: optional_string(item, "LastModifiedTime"),
        start_time_zone: optional_string(item, "StartTimeZoneId"),
        end_time_zone: optional_string(item, "EndTimeZoneId"),
    })
}

fn is_teams_join_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("teams.microsoft.com")
                || host.to_ascii_lowercase().ends_with(".teams.microsoft.com")
        })
    })
}

fn normalize_attendees(item: &Value, key: &str) -> Vec<CalendarAttendee> {
    item.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|attendee| {
            let mailbox = attendee.get("Mailbox")?;
            Some(CalendarAttendee {
                name: optional_string(mailbox, "Name"),
                email: optional_string(mailbox, "SmtpEmailAddress")
                    .or_else(|| optional_string(mailbox, "EmailAddress")),
                response_type: optional_string(attendee, "ResponseType"),
                attendance: optional_string(attendee, "Attendance"),
                response_mode: optional_string(attendee, "ResponseMode"),
            })
        })
        .collect()
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

fn unsigned(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::{is_teams_join_url, normalize, normalize_details};
    use crate::owa::{Week, WeekRange};
    use chrono::NaiveDate;
    use serde_json::json;

    #[test]
    fn recognizes_only_real_teams_join_hosts() {
        assert!(is_teams_join_url(
            "https://teams.microsoft.com/l/meetup-join/example"
        ));
        assert!(!is_teams_join_url(
            "https://teams.microsoft.com.example.test/l/meetup-join/example"
        ));
        assert!(!is_teams_join_url(
            "not a URL containing teams.microsoft.com"
        ));
    }

    #[test]
    fn normalizes_event_details_and_online_meeting_link() {
        let response = json!({
            "Body": {"ResponseMessages": {"Items": [{
                "ResponseClass": "Success",
                "ResponseCode": "NoError",
                "Items": [{
                    "ItemId": {"Id": "event-id", "ChangeKey": "change"},
                    "UID": "uid",
                    "Subject": "Meeting",
                    "Start": "2026-07-20T09:00:00-04:00",
                    "End": "2026-07-20T09:30:00-04:00",
                    "IsMeeting": true,
                    "IsOnlineMeeting": true,
                    "OnlineMeetingProvider": "TeamsForBusiness",
                    "OnlineMeetingJoinUrl": "https://teams.microsoft.com/l/meetup-join/example",
                    "OnlineMeetingChatId": "chat-id",
                    "Body": {"BodyType": "HTML", "Value": "<p>Agenda</p>"},
                    "RequiredAttendees": [{
                        "Mailbox": {"Name": "Person", "EmailAddress": "person@example.com"},
                        "ResponseType": "Accept"
                    }],
                    "ReminderIsSet": true,
                    "ReminderMinutesBeforeStart": 15
                }]
            }]}}
        });
        let event = normalize_details(&response).unwrap();
        assert_eq!(event.event.id, "event-id");
        assert!(event.event.teams_meeting);
        assert!(event.online_meeting);
        assert_eq!(
            event.online_meeting_join_url.as_deref(),
            Some("https://teams.microsoft.com/l/meetup-join/example")
        );
        assert_eq!(event.required_attendees.len(), 1);
        assert_eq!(event.body.unwrap().content, "<p>Agenda</p>");
        assert_eq!(event.reminder_minutes_before_start, Some(15));
    }

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

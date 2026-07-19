//! Private Outlook Web (OWA/Exchange) calendar transport.

use crate::session::AuthState;
use anyhow::Context;
use chrono::{Datelike, Duration as ChronoDuration, Local, NaiveDate};
use reqwest::StatusCode;
use reqwest::blocking::{Client, ClientBuilder, Response};
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt;
use std::time::Duration;

pub const DEFAULT_CLIENT_VERSION: &str = "20260710013.09";
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";
const SERVICE_ENDPOINT: &str = "https://outlook.cloud.microsoft/owa/service.svc";

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Week {
    Last,
    Current,
    Next,
}

impl fmt::Display for Week {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Last => "last",
            Self::Current => "current",
            Self::Next => "next",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WeekRange {
    pub start: NaiveDate,
    pub end_exclusive: NaiveDate,
}

impl WeekRange {
    pub fn for_today(week: Week, today: NaiveDate) -> Self {
        let current_sunday =
            today - ChronoDuration::days(i64::from(today.weekday().num_days_from_sunday()));
        let offset = match week {
            Week::Last => -7,
            Week::Current => 0,
            Week::Next => 7,
        };
        let start = current_sunday + ChronoDuration::days(offset);
        Self {
            start,
            end_exclusive: start + ChronoDuration::days(7),
        }
    }

    pub fn current(week: Week) -> Self {
        Self::for_today(week, Local::now().date_naive())
    }
}

fn wire_date(date: NaiveDate) -> String {
    format!("{}T00:00:00.000", date.format("%Y-%m-%d"))
}

#[derive(Debug)]
pub enum OwaError {
    Unauthorized,
    Failure(anyhow::Error),
}

impl fmt::Display for OwaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => formatter.write_str("Outlook rejected the access token"),
            Self::Failure(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for OwaError {}

impl From<reqwest::Error> for OwaError {
    fn from(error: reqwest::Error) -> Self {
        Self::Failure(error.into())
    }
}

pub fn get_bootstrap(auth: &AuthState) -> Result<String, OwaError> {
    let (access_token, anchor_mailbox, client_version) = auth_context(auth)?;
    let response = http_client()
        .map_err(OwaError::Failure)?
        .post("https://outlook.cloud.microsoft/owa/startupdata.ashx?app=Calendar&n=0")
        .header("authorization", format!("Bearer {access_token}"))
        .header("content-type", "application/json; charset=utf-8")
        .header("x-anchormailbox", anchor_mailbox)
        .header("x-client-version", client_version)
        .body(Vec::new())
        .send()?;
    parse_bootstrap(&response_json(response, "OWA startup data")?).map_err(OwaError::Failure)
}

pub fn get_calendar_view(
    auth: &AuthState,
    range: &WeekRange,
    time_zone: &str,
) -> Result<Value, OwaError> {
    let (access_token, anchor_mailbox, client_version) = auth_context(auth)?;
    let calendar_id = auth
        .calendar_id
        .as_deref()
        .ok_or_else(|| OwaError::Failure(anyhow::anyhow!("primary calendar id is missing")))?;
    let request = calendar_view_request(range, time_zone, calendar_id);
    let encoded = encode_owa_header(&request).map_err(OwaError::Failure)?;

    let response = http_client()
        .map_err(OwaError::Failure)?
        .post(format!(
            "{SERVICE_ENDPOINT}?action=GetCalendarView&app=Calendar&n=0"
        ))
        .header("authorization", format!("Bearer {access_token}"))
        .header("action", "GetCalendarView")
        .header("content-type", "application/json; charset=utf-8")
        .header(
            "prefer",
            "IdType=\"ImmutableId\", exchange.behavior=\"IncludeThirdPartyOnlineMeetingProviders\"",
        )
        .header("x-anchormailbox", anchor_mailbox)
        .header("x-client-version", client_version)
        .header("x-owa-actionsource", "GetCalendarView")
        .header("x-owa-hosted-ux", "false")
        .header("x-owa-urlpostdata", encoded)
        .header("x-req-source", "Calendar")
        .body(Vec::new())
        .send()?;
    let value = response_json(response, "OWA")?;
    let body = value.get("Body").unwrap_or(&Value::Null);
    let field = |key| body.get(key).and_then(Value::as_str).unwrap_or("unknown");
    let response_class = field("ResponseClass");
    let response_code = field("ResponseCode");
    if response_class != "Success" || response_code != "NoError" {
        return Err(OwaError::Failure(anyhow::anyhow!(
            "OWA GetCalendarView failed: class={response_class}, code={response_code}"
        )));
    }
    Ok(value)
}

fn auth_context(auth: &AuthState) -> Result<(&str, &str, &str), OwaError> {
    let access_token = auth
        .access_token
        .as_ref()
        .filter(|token| !token.value.is_empty())
        .ok_or_else(|| OwaError::Failure(anyhow::anyhow!("access token is missing")))?;
    let anchor_mailbox = auth
        .anchor_mailbox
        .as_deref()
        .ok_or_else(|| OwaError::Failure(anyhow::anyhow!("Outlook anchor mailbox is missing")))?;
    Ok((
        &access_token.value,
        anchor_mailbox,
        auth.client_version
            .as_deref()
            .unwrap_or(DEFAULT_CLIENT_VERSION),
    ))
}

fn response_json(response: Response, label: &str) -> Result<Value, OwaError> {
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(OwaError::Unauthorized);
    }
    let status = response.status();
    let bytes = response.bytes()?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        let snippet: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
        OwaError::Failure(anyhow::anyhow!(
            "{label} returned {status} with a non-JSON response: {snippet}"
        ))
    })?;
    if status.is_success() {
        Ok(value)
    } else {
        Err(OwaError::Failure(anyhow::anyhow!(
            "{label} returned {status}: {}",
            compact_error(&value)
        )))
    }
}

fn http_client() -> anyhow::Result<Client> {
    ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()
        .context("cannot build OWA HTTP client")
}

fn encode_owa_header(value: &Value) -> anyhow::Result<String> {
    let json = serde_json::to_string(value)?;
    // `x-owa-urlpostdata` is decoded like JavaScript `decodeURIComponent`, not
    // as form data. A literal `+` would therefore turn the Windows time-zone
    // id into `Eastern+Standard+Time` and OWA returns `TimeZoneException`.
    Ok(url::form_urlencoded::byte_serialize(json.as_bytes())
        .collect::<String>()
        .replace('+', "%20"))
}

fn parse_bootstrap(value: &Value) -> anyhow::Result<String> {
    let folders = value
        .pointer("/findFolders/Body/ResponseMessages/Items/0/RootFolder/Folders")
        .and_then(Value::as_array)
        .context("OWA startup data has no folder list")?;
    let calendar = folders
        .iter()
        .find(|folder| {
            folder.get("DistinguishedFolderId").and_then(Value::as_str) == Some("calendar")
        })
        .or_else(|| {
            folders.iter().find(|folder| {
                folder.get("FolderClass").and_then(Value::as_str) == Some("IPF.Appointment")
                    && folder.get("DisplayName").and_then(Value::as_str) == Some("Calendar")
            })
        })
        .context("primary Calendar folder was not present in OWA startup data")?;
    calendar
        .pointer("/FolderId/Id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .context("primary Calendar folder has no id")
}

fn calendar_view_request(range: &WeekRange, time_zone: &str, calendar_id: &str) -> Value {
    json!({
        "__type": "GetCalendarViewJsonRequest:#Exchange",
        "Header": {
            "__type": "JsonRequestHeaders:#Exchange",
            "RequestServerVersion": "V2018_01_08",
            "TimeZoneContext": {
                "__type": "TimeZoneContext:#Exchange",
                "TimeZoneDefinition": {
                    "__type": "TimeZoneDefinitionType:#Exchange",
                    "Id": time_zone
                }
            }
        },
        "Body": {
            "__type": "GetCalendarViewRequest:#Exchange",
            "CalendarId": {
                "__type": "TargetFolderId:#Exchange",
                "BaseFolderId": {
                    "__type": "FolderId:#Exchange",
                    "Id": calendar_id
                }
            },
            "RangeStart": wire_date(range.start),
            "RangeEnd": wire_date(range.end_exclusive),
            "ClientSupportsIrm": true,
            "OptimizeExtendedPropertyLoading": true
        }
    })
}

fn compact_error(value: &Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "unknown OWA error".to_string())
        .chars()
        .take(500)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Week, WeekRange, calendar_view_request, encode_owa_header, parse_bootstrap};
    use chrono::NaiveDate;

    #[test]
    fn week_ranges_start_on_sunday() {
        let friday = NaiveDate::from_ymd_opt(2026, 7, 17).unwrap();
        let current = WeekRange::for_today(Week::Current, friday);
        assert_eq!(current.start, NaiveDate::from_ymd_opt(2026, 7, 12).unwrap());
        assert_eq!(
            current.end_exclusive,
            NaiveDate::from_ymd_opt(2026, 7, 19).unwrap()
        );
        assert_eq!(
            WeekRange::for_today(Week::Last, friday).start,
            NaiveDate::from_ymd_opt(2026, 7, 5).unwrap()
        );
        assert_eq!(
            WeekRange::for_today(Week::Next, friday).start,
            NaiveDate::from_ymd_opt(2026, 7, 19).unwrap()
        );
    }

    #[test]
    fn parses_primary_calendar_from_startup_data() {
        let bootstrap = parse_bootstrap(&serde_json::json!({
            "findFolders": {"Body": {"ResponseMessages": {"Items": [{
                "RootFolder": {"Folders": [{
                    "DistinguishedFolderId": "calendar",
                    "FolderId": {"Id": "folder-id"}
                }]}
            }]}}}
        }))
        .unwrap();
        assert_eq!(bootstrap, "folder-id");
    }

    #[test]
    fn request_uses_resolved_calendar_folder() {
        let range = WeekRange {
            start: NaiveDate::from_ymd_opt(2026, 7, 12).unwrap(),
            end_exclusive: NaiveDate::from_ymd_opt(2026, 7, 19).unwrap(),
        };
        let request = calendar_view_request(&range, "Eastern Standard Time", "folder-id");
        assert_eq!(
            request["Body"]["CalendarId"]["BaseFolderId"]["Id"],
            "folder-id"
        );
        assert_eq!(request["Body"]["RangeStart"], "2026-07-12T00:00:00.000");
        let encoded = encode_owa_header(&request).unwrap();
        assert!(encoded.contains("Eastern%20Standard%20Time"));
        assert!(!encoded.contains("Eastern+Standard+Time"));
    }
}

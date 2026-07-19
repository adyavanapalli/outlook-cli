//! Private Outlook Web (OWA/Exchange) calendar transport.

use crate::session::AuthState;
use anyhow::Context;
use chrono::{Datelike, Duration as ChronoDuration, Local, NaiveDate};
use reqwest::StatusCode;
use reqwest::blocking::{Client, ClientBuilder, Response};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::fmt;
use std::time::Duration;
use uuid::Uuid;

pub const DEFAULT_CLIENT_VERSION: &str = "20260710013.09";
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";
const SERVICE_ENDPOINT: &str = "https://outlook.cloud.microsoft/owa/service.svc";
const SEARCH_ENDPOINT: &str = "https://outlook.cloud.microsoft/searchservice/api/v2/query";
const IMMUTABLE_ID_PREFERENCE: &str =
    "IdType=\"ImmutableId\", exchange.behavior=\"IncludeThirdPartyOnlineMeetingProviders\"";
const SEARCH_ATTEMPTS: usize = 3;

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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MailFolder<'a> {
    Distinguished(&'a str),
    Id(&'a str),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MailSearchFolder<'a> {
    All,
    Current(&'a str),
    Subfolders(&'a [String]),
}

#[derive(Copy, Clone, Debug)]
pub struct MailSearchQuery<'a> {
    pub query: &'a str,
    pub folder: MailSearchFolder<'a>,
    pub offset: usize,
    pub limit: usize,
    pub start: Option<NaiveDate>,
    pub end: Option<NaiveDate>,
    pub has_attachments: bool,
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
        .header("prefer", IMMUTABLE_ID_PREFERENCE)
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

pub fn get_calendar_event(
    auth: &AuthState,
    item_id: &str,
    time_zone: &str,
) -> Result<Value, OwaError> {
    let (access_token, anchor_mailbox, client_version) = auth_context(auth)?;
    let body = serde_json::to_vec(&calendar_event_request(item_id, time_zone))
        .map_err(|error| OwaError::Failure(error.into()))?;
    let response = http_client()
        .map_err(OwaError::Failure)?
        .post(format!(
            "{SERVICE_ENDPOINT}?action=GetCalendarEvent&app=Calendar&n=0"
        ))
        .header("authorization", format!("Bearer {access_token}"))
        .header("action", "GetCalendarEvent")
        .header("content-type", "application/json; charset=utf-8")
        .header("prefer", IMMUTABLE_ID_PREFERENCE)
        .header("x-anchormailbox", anchor_mailbox)
        .header("x-client-version", client_version)
        .header("x-owa-actionsource", "GetCalendarEvent")
        .header("x-owa-hosted-ux", "false")
        .header("x-req-source", "Calendar")
        .body(body)
        .send()?;
    let value = response_json(response, "OWA GetCalendarEvent")?;
    validate_calendar_event_response(&value)?;
    Ok(value)
}

pub fn get_mail_startup(auth: &AuthState) -> Result<Value, OwaError> {
    let (access_token, anchor_mailbox, client_version) = auth_context(auth)?;
    let response = http_client()
        .map_err(OwaError::Failure)?
        .post("https://outlook.cloud.microsoft/owa/startupdata.ashx?app=Mail&n=0")
        .header("authorization", format!("Bearer {access_token}"))
        .header("action", "StartupData")
        .header("prefer", IMMUTABLE_ID_PREFERENCE)
        .header("x-anchormailbox", anchor_mailbox)
        .header("x-client-version", client_version)
        .header("x-message-count", "25")
        .header("x-owa-actionsource", "StartupData")
        .header("x-owa-hosted-ux", "false")
        .header("x-req-source", "Mail")
        .body(Vec::new())
        .send()?;
    response_json(response, "OWA mail startup data")
}

pub fn find_mail_items(
    auth: &AuthState,
    folder: MailFolder<'_>,
    view_filter: &str,
    offset: usize,
    limit: usize,
    time_zone: &str,
) -> Result<Value, OwaError> {
    let request = find_mail_items_request(folder, view_filter, offset, limit, time_zone);
    post_mail_service(auth, "FindItem", "FindItem", None, &request)
}

pub fn get_mail_item(auth: &AuthState, item_id: &str, time_zone: &str) -> Result<Value, OwaError> {
    let request = get_mail_item_request(item_id, time_zone);
    post_mail_service(
        auth,
        "GetItem",
        "LoadItem_ListViewSelectionChange",
        Some("0"),
        &request,
    )
}

pub fn search_mail(
    auth: &AuthState,
    query: &MailSearchQuery<'_>,
    time_zone: &str,
) -> Result<Value, OwaError> {
    let (access_token, anchor_mailbox, client_version) = auth_context(auth)?;
    let body = serde_json::to_vec(&mail_search_request(query, time_zone))
        .map_err(|error| OwaError::Failure(error.into()))?;
    let client = http_client().map_err(OwaError::Failure)?;
    for attempt in 0..SEARCH_ATTEMPTS {
        let response = match client
            .post(SEARCH_ENDPOINT)
            .query(&[("n", "0"), ("cv", client_version)])
            .header("authorization", format!("Bearer {access_token}"))
            .header("content-type", "application/json")
            .header("prefer", IMMUTABLE_ID_PREFERENCE)
            .header("x-anchormailbox", anchor_mailbox)
            .header("x-client-version", client_version)
            .header("x-owa-hosted-ux", "false")
            .header("x-req-source", "Mail")
            .body(body.clone())
            .send()
        {
            Ok(response) => response,
            Err(error)
                if attempt + 1 < SEARCH_ATTEMPTS && (error.is_connect() || error.is_timeout()) =>
            {
                search_retry_delay(attempt);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let (status, value) = response_parts(response, "Outlook mail search")?;
        if status.is_success() {
            return Ok(value);
        }
        if attempt + 1 < SEARCH_ATTEMPTS && transient_search_failure(status, &value) {
            search_retry_delay(attempt);
            continue;
        }
        return Err(http_failure("Outlook mail search", status, &value));
    }
    Err(OwaError::Failure(anyhow::anyhow!(
        "Outlook mail search exhausted its retry attempts"
    )))
}

fn post_mail_service(
    auth: &AuthState,
    action: &str,
    action_source: &str,
    priority: Option<&str>,
    request: &Value,
) -> Result<Value, OwaError> {
    let (access_token, anchor_mailbox, client_version) = auth_context(auth)?;
    let body = serde_json::to_vec(request).map_err(|error| OwaError::Failure(error.into()))?;
    let mut builder = http_client()
        .map_err(OwaError::Failure)?
        .post(SERVICE_ENDPOINT)
        .query(&[("action", action), ("app", "Mail"), ("n", "0")])
        .header("authorization", format!("Bearer {access_token}"))
        .header("action", action)
        .header("content-type", "application/json; charset=utf-8")
        .header("prefer", IMMUTABLE_ID_PREFERENCE)
        .header("x-anchormailbox", anchor_mailbox)
        .header("x-client-version", client_version)
        .header("x-owa-actionsource", action_source)
        .header("x-owa-hosted-ux", "false")
        .header("x-req-source", "Mail");
    if let Some(priority) = priority {
        builder = builder.header("x-owa-priority", priority);
    }
    let response = builder.body(body).send()?;
    response_json(response, &format!("OWA {action}"))
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
    let (status, value) = response_parts(response, label)?;
    if status.is_success() {
        Ok(value)
    } else {
        Err(http_failure(label, status, &value))
    }
}

fn response_parts(response: Response, label: &str) -> Result<(StatusCode, Value), OwaError> {
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(OwaError::Unauthorized);
    }
    let status = response.status();
    let bytes = response.bytes()?;
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok((status, value)),
        Err(_) if !status.is_success() => Ok((status, Value::Null)),
        Err(_) => Err(OwaError::Failure(anyhow::anyhow!(
            "{label} returned {status} with a non-JSON response (body omitted)"
        ))),
    }
}

fn http_failure(label: &str, status: StatusCode, value: &Value) -> OwaError {
    OwaError::Failure(anyhow::anyhow!(
        "{label} returned {status}: {}",
        compact_error(value)
    ))
}

fn transient_search_failure(status: StatusCode, value: &Value) -> bool {
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return true;
    }
    status == StatusCode::BAD_REQUEST
        && serde_json::to_string(value).is_ok_and(|body| {
            body.contains("FanoutExternalBadRequest")
                || body.contains("TwoStepFanout_FirstStepFailed")
        })
}

fn search_retry_delay(attempt: usize) {
    std::thread::sleep(Duration::from_millis(250 * (attempt as u64 + 1)));
}

fn validate_calendar_event_response(value: &Value) -> Result<(), OwaError> {
    let message = value
        .pointer("/Body/ResponseMessages/Items/0")
        .unwrap_or(&Value::Null);
    let field = |key| {
        message
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    };
    let response_class = field("ResponseClass");
    let response_code = field("ResponseCode");
    if response_class != "Success" || response_code != "NoError" {
        return Err(OwaError::Failure(anyhow::anyhow!(
            "OWA GetCalendarEvent failed: class={response_class}, code={response_code}"
        )));
    }
    Ok(())
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

fn calendar_event_request(item_id: &str, time_zone: &str) -> Value {
    // This endpoint returns the standard event fields with IdOnly; Outlook Web
    // uses the same shape and treats MaximumBodySize=0 as an unbounded body.
    json!({
        "__type": "GetCalendarEventJsonRequest:#Exchange",
        "Header": exchange_header("V2018_01_08", time_zone),
        "Body": {
            "__type": "GetCalendarEventRequest:#Exchange",
            "EventIds": [{
                "__type": "ItemId:#Exchange",
                "Id": item_id
            }],
            "ItemShape": {
                "BaseShape": "IdOnly",
                "BodyType": "HTML",
                "FilterHtmlContent": true,
                "AddBlankTargetToLinks": true,
                "ImageProxyCapability": "OwaAndConnectorsProxy",
                "ClientSupportsIrm": true,
                "MaximumBodySize": 0,
                "BlockExternalImages": true,
                "BlockContentFromUnknownSenders": true
            },
            "DraftOnlineMeetingSupport": true
        }
    })
}

fn find_mail_items_request(
    folder: MailFolder<'_>,
    view_filter: &str,
    offset: usize,
    limit: usize,
    time_zone: &str,
) -> Value {
    json!({
        "__type": "FindItemJsonRequest:#Exchange",
        "Header": exchange_header("V2018_01_08", time_zone),
        "Body": {
            "__type": "FindItemRequest:#Exchange",
            "ParentFolderIds": [mail_folder_json(folder)],
            "ItemShape": {
                "__type": "ItemResponseShape:#Exchange",
                "BaseShape": "IdOnly",
                "AdditionalProperties": [
                    {
                        "__type": "PropertyUri:#Exchange",
                        "FieldURI": "CopilotInboxHeadline"
                    },
                    {
                        "__type": "PropertyUri:#Exchange",
                        "FieldURI": "DeferredSendTime"
                    }
                ]
            },
            "ShapeName": "MailListItem",
            "Paging": {
                "__type": "IndexedPageView:#Exchange",
                "BasePoint": "Beginning",
                "Offset": offset,
                "MaxEntriesReturned": limit
            },
            "ViewFilter": view_filter,
            "SortOrder": [
                {
                    "__type": "SortResults:#Exchange",
                    "Order": "Descending",
                    "Path": {
                        "__type": "PropertyUri:#Exchange",
                        "FieldURI": "ReceivedOrRenewTime"
                    }
                },
                {
                    "__type": "SortResults:#Exchange",
                    "Order": "Descending",
                    "Path": {
                        "__type": "PropertyUri:#Exchange",
                        "FieldURI": "DateTimeReceived"
                    }
                }
            ],
            "FocusedViewFilter": -1,
            "Traversal": "Shallow"
        }
    })
}

fn get_mail_item_request(item_id: &str, time_zone: &str) -> Value {
    json!({
        "__type": "GetItemJsonRequest:#Exchange",
        "Header": exchange_header("V2017_08_18", time_zone),
        "Body": {
            "__type": "GetItemRequest:#Exchange",
            "ItemShape": {
                "__type": "ItemResponseShape:#Exchange",
                "BaseShape": "IdOnly",
                "AddBlankTargetToLinks": true,
                "BlockContentFromUnknownSenders": false,
                "BlockExternalImagesIfSenderUntrusted": true,
                "ClientSupportsIrm": true,
                "FilterHtmlContent": true,
                "FilterInlineSafetyTips": true,
                "MaximumBodySize": 2_097_152,
                "MaximumRecipientsToReturn": 20,
                "ImageProxyCapability": "OwaAndConnectorsProxy"
            },
            "ItemIds": [{
                "__type": "ItemId:#Exchange",
                "Id": item_id
            }],
            "ShapeName": "ItemNormalizedBody"
        }
    })
}

fn mail_search_request(query: &MailSearchQuery<'_>, time_zone: &str) -> Value {
    // SearchService v2 interprets Size as an end position rather than a page
    // length: Outlook sends From=25, Size=50 for the second 25-item window.
    let end_position = query.offset.saturating_add(query.limit);
    let refining_queries = if query.has_attachments {
        json!([{
            "RefinerString": "ShallowRefiner::SearchScope:hasattachment:true"
        }])
    } else {
        Value::Null
    };
    json!({
        "Cvid": Uuid::new_v4().to_string(),
        "Scenario": {"Name": "owa.react"},
        "TimeZone": time_zone,
        "TextDecorations": "Off",
        "EntityRequests": [{
            "EntityType": "Message",
            "ContentSources": ["Exchange", "ExchangeArchive"],
            "Filter": mail_search_filter(query),
            "From": query.offset,
            "Query": {"QueryString": query.query},
            "RefiningQueries": refining_queries,
            "Size": end_position,
            "Sort": [
                {"Field": "Score", "SortDirection": "Desc", "Count": 7},
                {"Field": "Time", "SortDirection": "Desc"}
            ],
            "EnableTopResults": true,
            "TopResultsCount": 7
        }],
        "QueryAlterationOptions": {
            "EnableSuggestion": true,
            "EnableAlteration": true,
            "SupportedRecourseDisplayTypes": [
                "Suggestion",
                "NoResultModification",
                "NoResultFolderRefinerModification",
                "NoRequeryModification",
                "Modification"
            ]
        },
        "LogicalId": Uuid::new_v4().to_string()
    })
}

fn mail_search_filter(query: &MailSearchQuery<'_>) -> Value {
    // Outlook Web includes Deleted Items alongside every selected UI scope.
    let folder = match query.folder {
        MailSearchFolder::All => json!({
            "Or": [
                {"Term": {"DistinguishedFolderName": "msgfolderroot"}},
                {"Term": {"DistinguishedFolderName": "DeletedItems"}}
            ]
        }),
        MailSearchFolder::Current(id) => json!({
            "Or": [
                {"Term": {"FolderId": id}},
                {"Term": {"DistinguishedFolderName": "DeletedItems"}}
            ]
        }),
        MailSearchFolder::Subfolders(ids) => {
            let mut folders = ids
                .iter()
                .map(|id| json!({"Term": {"FolderId": id}}))
                .collect::<Vec<_>>();
            folders.push(json!({
                "Term": {"DistinguishedFolderName": "DeletedItems"}
            }));
            json!({"Or": folders})
        }
    };
    if query.start.is_none() && query.end.is_none() {
        return folder;
    }
    let mut received = Map::new();
    if let Some(start) = query.start {
        received.insert("gte".to_string(), json!(search_date(start)));
    }
    if let Some(end) = query.end {
        received.insert("lte".to_string(), json!(search_date(end)));
    }
    json!({
        "And": [
            {"Range": {"received": received}},
            folder
        ]
    })
}

fn mail_folder_json(folder: MailFolder<'_>) -> Value {
    match folder {
        MailFolder::Distinguished(id) => json!({
            "__type": "DistinguishedFolderId:#Exchange",
            "Id": id
        }),
        MailFolder::Id(id) => json!({
            "__type": "FolderId:#Exchange",
            "Id": id
        }),
    }
}

fn exchange_header(version: &str, time_zone: &str) -> Value {
    json!({
        "__type": "JsonRequestHeaders:#Exchange",
        "RequestServerVersion": version,
        "TimeZoneContext": {
            "__type": "TimeZoneContext:#Exchange",
            "TimeZoneDefinition": {
                "__type": "TimeZoneDefinitionType:#Exchange",
                "Id": time_zone
            }
        }
    })
}

fn search_date(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

fn compact_error(value: &Value) -> String {
    let mut metadata = Vec::new();
    collect_error_metadata(value, &mut metadata);
    if metadata.is_empty() {
        "details omitted".to_string()
    } else {
        metadata.join(", ")
    }
}

fn collect_error_metadata(value: &Value, metadata: &mut Vec<String>) {
    if metadata.len() >= 8 {
        return;
    }
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                let normalized = key.to_ascii_lowercase();
                if matches!(
                    normalized.as_str(),
                    "code"
                        | "errorcode"
                        | "responsecode"
                        | "responseclass"
                        | "traceid"
                        | "requestid"
                        | "correlationid"
                        | "httpcode"
                ) && let Some(value) = safe_error_metadata_value(value)
                {
                    metadata.push(format!("{key}={value}"));
                }
                collect_error_metadata(value, metadata);
                if metadata.len() >= 8 {
                    break;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_error_metadata(value, metadata);
                if metadata.len() >= 8 {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn safe_error_metadata_value(value: &Value) -> Option<String> {
    if let Some(value) = value.as_u64() {
        return Some(value.to_string());
    }
    let value = value.as_str()?;
    (value.len() <= 100
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.:#".contains(character)))
    .then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        MailFolder, MailSearchFolder, MailSearchQuery, Week, WeekRange, calendar_event_request,
        calendar_view_request, compact_error, encode_owa_header, find_mail_items_request,
        get_mail_item_request, mail_search_request, parse_bootstrap, transient_search_failure,
    };
    use chrono::NaiveDate;
    use reqwest::StatusCode;

    #[test]
    fn error_summaries_include_only_safe_metadata() {
        let summary = compact_error(&serde_json::json!({
            "Instrumentation": {"TraceId": "trace-123"},
            "error": {
                "code": "InvalidQuery",
                "message": "secret@example.com searched for confidential subject"
            }
        }));
        assert!(summary.contains("code=InvalidQuery"));
        assert!(summary.contains("TraceId=trace-123"));
        assert!(!summary.contains("secret@example.com"));
        assert!(!summary.contains("confidential subject"));
    }

    #[test]
    fn recognizes_only_transient_search_failures() {
        assert!(transient_search_failure(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"code": "FanoutExternalBadRequest"})
        ));
        assert!(transient_search_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            &serde_json::json!({})
        ));
        assert!(!transient_search_failure(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"code": "InvalidQuery"})
        ));
    }

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

    #[test]
    fn calendar_get_request_asks_for_online_meeting_details() {
        let request = calendar_event_request("item-id", "Eastern Standard Time");
        assert_eq!(request["Body"]["EventIds"][0]["Id"], "item-id");
        assert_eq!(request["Body"]["ItemShape"]["BaseShape"], "IdOnly");
        assert_eq!(request["Body"]["ItemShape"]["BodyType"], "HTML");
        assert_eq!(request["Body"]["ItemShape"]["BlockExternalImages"], true);
        assert_eq!(request["Body"]["DraftOnlineMeetingSupport"], true);
    }

    #[test]
    fn mail_list_request_encodes_folder_filter_and_page() {
        let request = find_mail_items_request(
            MailFolder::Distinguished("inbox"),
            "Unread",
            25,
            50,
            "Eastern Standard Time",
        );
        assert_eq!(request["Body"]["ParentFolderIds"][0]["Id"], "inbox");
        assert_eq!(
            request["Body"]["ParentFolderIds"][0]["__type"],
            "DistinguishedFolderId:#Exchange"
        );
        assert_eq!(request["Body"]["ViewFilter"], "Unread");
        assert_eq!(request["Body"]["Paging"]["Offset"], 25);
        assert_eq!(request["Body"]["Paging"]["MaxEntriesReturned"], 50);
    }

    #[test]
    fn mail_get_request_uses_normalized_filtered_body() {
        let request = get_mail_item_request("item-id", "Eastern Standard Time");
        assert_eq!(request["Body"]["ItemIds"][0]["Id"], "item-id");
        assert_eq!(request["Body"]["ShapeName"], "ItemNormalizedBody");
        assert_eq!(request["Body"]["ItemShape"]["FilterHtmlContent"], true);
        assert_eq!(
            request["Body"]["ItemShape"]["BlockExternalImagesIfSenderUntrusted"],
            true
        );
    }

    #[test]
    fn mail_search_request_encodes_subfolders_dates_and_attachment_refiner() {
        let folders = vec!["folder-id".to_string(), "child-id".to_string()];
        let query = MailSearchQuery {
            query: "subject:(release) hasattachments:yes",
            folder: MailSearchFolder::Subfolders(&folders),
            offset: 25,
            limit: 50,
            start: Some(NaiveDate::from_ymd_opt(2026, 7, 1).unwrap()),
            end: Some(NaiveDate::from_ymd_opt(2026, 7, 18).unwrap()),
            has_attachments: true,
        };
        let request = mail_search_request(&query, "Eastern Standard Time");
        let entity = &request["EntityRequests"][0];
        assert_eq!(entity["From"], 25);
        assert_eq!(entity["Size"], 75);
        assert_eq!(
            entity["Filter"]["And"][0]["Range"]["received"]["gte"],
            "2026-07-01"
        );
        assert_eq!(
            entity["Filter"]["And"][1]["Or"][0]["Term"]["FolderId"],
            "folder-id"
        );
        assert_eq!(
            entity["Filter"]["And"][1]["Or"][1]["Term"]["FolderId"],
            "child-id"
        );
        assert_eq!(
            entity["RefiningQueries"][0]["RefinerString"],
            "ShallowRefiner::SearchScope:hasattachment:true"
        );
    }
}

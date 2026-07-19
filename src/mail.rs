//! `outlook mail` commands, filters, and stable JSON projections.

use crate::auth;
use crate::output;
use crate::owa::{self, MailFolder, MailSearchFolder, MailSearchQuery, OwaError};
use crate::session::{AuthState, SessionFile, Store};
use anyhow::Context;
use chrono::NaiveDate;
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

const DEFAULT_PAGE_SIZE: usize = 25;
const MAX_PAGE_SIZE: usize = 50;

#[derive(Subcommand)]
pub enum MailSubcommand {
    /// List available mailbox folders and their unread counts
    Folders {
        /// Emit the unmodified OWA folder response
        #[arg(long)]
        raw: bool,
    },
    /// List messages in one folder
    List(MailListArgs),
    /// Retrieve one message and its normalized body by immutable item ID
    Get(MailGetArgs),
    /// Search messages across the mailbox or within a folder
    Search(Box<MailSearchArgs>),
}

#[derive(Args)]
pub struct MailListArgs {
    /// Distinguished or display folder name (defaults to inbox)
    #[arg(long)]
    folder: Option<String>,
    /// Immutable folder ID from `outlook mail folders`
    #[arg(long)]
    folder_id: Option<String>,
    /// Folder view filter
    #[arg(long, value_enum, default_value_t = MailViewFilter::All)]
    filter: MailViewFilter,
    /// Zero-based result offset
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// Number of messages to return (1-50)
    #[arg(long, default_value_t = DEFAULT_PAGE_SIZE)]
    limit: usize,
    /// Emit the unmodified OWA response
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
pub struct MailGetArgs {
    /// Immutable item ID returned by list or search
    id: String,
    /// Emit the unmodified OWA response
    #[arg(long)]
    raw: bool,
}

/// Independent switches mirror Outlook's combinable search refiners.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args)]
pub struct MailSearchArgs {
    /// Free-text or Outlook search expression
    query: Option<String>,
    /// Folder scope to search
    #[arg(long, value_enum, default_value_t = SearchScope::AllFolders)]
    scope: SearchScope,
    /// Distinguished or display folder name for current-folder/subfolders scope
    #[arg(long)]
    folder: Option<String>,
    /// Immutable folder ID for current-folder/subfolders scope
    #[arg(long)]
    folder_id: Option<String>,
    /// Sender address; repeat to match any supplied sender
    #[arg(long = "from")]
    from: Vec<String>,
    /// To recipient; repeat to match any supplied recipient
    #[arg(long)]
    to: Vec<String>,
    /// Cc recipient; repeat to match any supplied recipient
    #[arg(long)]
    cc: Vec<String>,
    /// Bcc recipient; repeat to match any supplied recipient
    #[arg(long)]
    bcc: Vec<String>,
    /// Subject expression
    #[arg(long)]
    subject: Option<String>,
    /// Additional keyword expression
    #[arg(long)]
    keywords: Option<String>,
    /// Message-body expression
    #[arg(long)]
    body: Option<String>,
    /// Inclusive earliest received date (YYYY-MM-DD)
    #[arg(long)]
    after: Option<NaiveDate>,
    /// Inclusive latest received date (YYYY-MM-DD)
    #[arg(long)]
    before: Option<NaiveDate>,
    /// Read-state filter
    #[arg(long, value_enum, default_value_t = SearchReadStatus::All)]
    read_status: SearchReadStatus,
    /// Require messages with attachments
    #[arg(long, visible_alias = "attachments")]
    has_attachments: bool,
    /// Require flagged messages
    #[arg(long)]
    flagged: bool,
    /// Importance filter
    #[arg(long, value_enum, default_value_t = SearchImportance::All)]
    importance: SearchImportance,
    /// Category name
    #[arg(long)]
    category: Option<String>,
    /// Require messages that mention the current account
    #[arg(long)]
    mentions_me: bool,
    /// Require messages addressed to the current account
    #[arg(long)]
    to_me: bool,
    /// Zero-based result offset
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// Number of search results to return (1-50)
    #[arg(long, default_value_t = DEFAULT_PAGE_SIZE)]
    limit: usize,
    /// Emit the unmodified `SearchService` response
    #[arg(long)]
    raw: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum MailViewFilter {
    All,
    Unread,
    Flagged,
    ToMe,
    HasFiles,
    MentionsMe,
    HasCalendarInvites,
}

impl MailViewFilter {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Unread => "Unread",
            Self::Flagged => "Flagged",
            Self::ToMe => "ToOrCcMe",
            Self::HasFiles => "HasFile",
            Self::MentionsMe => "Mentioned",
            Self::HasCalendarInvites => "HasCalendarInvite",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SearchScope {
    AllFolders,
    CurrentFolder,
    Subfolders,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SearchReadStatus {
    All,
    Read,
    Unread,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SearchImportance {
    All,
    High,
    Normal,
    Low,
}

#[derive(Serialize)]
struct MailFolderList {
    count: usize,
    folders: Vec<MailFolderInfo>,
}

#[derive(Serialize)]
struct MailFolderInfo {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distinguished_name: Option<String>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unread_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    child_folder_count: Option<u64>,
}

#[derive(Serialize)]
struct MailList {
    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder_id: Option<String>,
    filter: MailViewFilter,
    offset: usize,
    next_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u64>,
    more: bool,
    count: usize,
    messages: Vec<MailMessageSummary>,
}

/// Stable JSON projection of independent message state flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct MailMessageSummary {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_id: Option<String>,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<MailAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<MailAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    received_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sent_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_at: Option<String>,
    read: bool,
    draft: bool,
    has_attachments: bool,
    flagged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    importance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitivity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inference_classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_folder_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    categories: Vec<String>,
}

#[derive(Serialize)]
struct MailAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

#[derive(Serialize)]
struct MailMessage {
    #[serde(flatten)]
    summary: MailMessageSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    to: Vec<MailAddress>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cc: Vec<MailAddress>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bcc: Vec<MailAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    received_representing: Option<MailAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internet_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<MailBody>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<MailAttachment>,
    has_blocked_images: bool,
}

#[derive(Serialize)]
struct MailBody {
    content_type: String,
    truncated: bool,
    content: String,
}

#[derive(Serialize)]
struct MailAttachment {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    inline: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_at: Option<String>,
}

#[derive(Serialize)]
struct MailSearchResults {
    query: String,
    scope: SearchScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder_id: Option<String>,
    offset: usize,
    next_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u64>,
    more: bool,
    partial: bool,
    count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    search_terms: Vec<String>,
    results: Vec<MailSearchHit>,
}

#[derive(Serialize)]
struct MailSearchHit {
    #[serde(flatten)]
    message: MailMessageSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    rank: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    highlighted_summary: Option<String>,
}

pub fn run(store: &Store, command: MailSubcommand) -> anyhow::Result<()> {
    match command {
        MailSubcommand::Folders { raw } => folders(store, raw),
        MailSubcommand::List(arguments) => list(store, &arguments),
        MailSubcommand::Get(arguments) => get(store, &arguments),
        MailSubcommand::Search(arguments) => search(store, &arguments),
    }
}

fn folders(store: &Store, raw: bool) -> anyhow::Result<()> {
    let (_session_lock, mut session) = authenticated_session(store)?;
    let response = request_with_retry(store, &mut session, owa::get_mail_startup)?;
    let folder_response = response.get("findFolders").unwrap_or(&response);
    validate_mail_response(folder_response, "FindFolder")?;
    if raw {
        return output::json(folder_response);
    }
    output::json(&normalize_folders(&response)?)
}

fn list(store: &Store, arguments: &MailListArgs) -> anyhow::Result<()> {
    validate_page(arguments.offset, arguments.limit)?;
    validate_folder_options(arguments.folder.as_deref(), arguments.folder_id.as_deref())?;
    let folder_label = arguments.folder.as_deref().map_or("inbox", str::trim);
    let (_session_lock, mut session) = authenticated_session(store)?;
    let mut resolved_id = arguments
        .folder_id
        .as_deref()
        .map(str::trim)
        .map(ToString::to_string);
    let distinguished = if resolved_id.is_none() {
        distinguished_folder_name(folder_label)
    } else {
        None
    };
    if resolved_id.is_none() && distinguished.is_none() {
        let startup = request_with_retry(store, &mut session, owa::get_mail_startup)?;
        resolved_id = Some(resolve_folder_id(&startup, folder_label)?);
    }
    let time_zone = session.config.timezone.clone();
    let response = request_with_retry(store, &mut session, |auth| {
        let folder = resolved_id.as_deref().map_or_else(
            || MailFolder::Distinguished(distinguished.unwrap_or("inbox")),
            MailFolder::Id,
        );
        owa::find_mail_items(
            auth,
            folder,
            arguments.filter.wire_name(),
            arguments.offset,
            arguments.limit,
            &time_zone,
        )
    })?;
    validate_mail_response(&response, "FindItem")?;
    if arguments.raw {
        return output::json(&response);
    }
    output::json(&normalize_list(
        arguments
            .folder_id
            .is_none()
            .then(|| folder_label.to_string()),
        resolved_id,
        arguments.filter,
        arguments.offset,
        &response,
    )?)
}

fn get(store: &Store, arguments: &MailGetArgs) -> anyhow::Result<()> {
    let id = validate_required_value(&arguments.id, "message ID")?;
    let (_session_lock, mut session) = authenticated_session(store)?;
    let time_zone = session.config.timezone.clone();
    let response = request_with_retry(store, &mut session, |auth| {
        owa::get_mail_item(auth, id, &time_zone)
    })?;
    validate_mail_response(&response, "GetItem")?;
    if arguments.raw {
        return output::json(&response);
    }
    output::json(&normalize_message(&response)?)
}

fn search(store: &Store, arguments: &MailSearchArgs) -> anyhow::Result<()> {
    validate_search(arguments)?;
    let query = build_search_query(arguments)?;
    let (_session_lock, mut session) = authenticated_session(store)?;
    let mut folder_id = arguments
        .folder_id
        .as_deref()
        .map(str::trim)
        .map(ToString::to_string);
    let folder_label = arguments
        .folder
        .as_deref()
        .map(str::trim)
        .map(ToString::to_string)
        .or_else(|| {
            (!matches!(arguments.scope, SearchScope::AllFolders) && folder_id.is_none())
                .then(|| "inbox".to_string())
        });
    let mut subfolder_ids = Vec::new();
    match arguments.scope {
        SearchScope::CurrentFolder if folder_id.is_none() => {
            let startup = request_with_retry(store, &mut session, owa::get_mail_startup)?;
            folder_id = Some(resolve_folder_id(
                &startup,
                folder_label.as_deref().unwrap_or("inbox"),
            )?);
        }
        SearchScope::Subfolders => {
            let startup = request_with_retry(store, &mut session, owa::get_mail_startup)?;
            if folder_id.is_none() {
                folder_id = Some(resolve_folder_id(
                    &startup,
                    folder_label.as_deref().unwrap_or("inbox"),
                )?);
            }
            subfolder_ids = folder_and_descendant_ids(
                &startup,
                folder_id
                    .as_deref()
                    .context("mail search folder ID is missing")?,
            )?;
        }
        SearchScope::AllFolders | SearchScope::CurrentFolder => {}
    }
    let folder = match arguments.scope {
        SearchScope::AllFolders => MailSearchFolder::All,
        SearchScope::CurrentFolder => MailSearchFolder::Current(
            folder_id
                .as_deref()
                .context("mail search folder ID is missing")?,
        ),
        SearchScope::Subfolders => MailSearchFolder::Subfolders(&subfolder_ids),
    };
    let time_zone = session.config.timezone.clone();
    let response = request_with_retry(store, &mut session, |auth| {
        owa::search_mail(
            auth,
            &MailSearchQuery {
                query: &query,
                folder,
                offset: arguments.offset,
                limit: arguments.limit,
                start: arguments.after,
                end: arguments.before,
                has_attachments: arguments.has_attachments,
            },
            &time_zone,
        )
    })?;
    if arguments.raw {
        return output::json(&response);
    }
    output::json(&normalize_search(
        query,
        arguments.scope,
        folder_label,
        folder_id,
        arguments.offset,
        arguments.limit,
        &response,
    )?)
}

fn authenticated_session(store: &Store) -> anyhow::Result<(std::fs::File, SessionFile)> {
    let session_lock = store.acquire_session_lock()?;
    let mut session = store.load()?;
    auth::ensure_access(store, &mut session, false)?;
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

fn validate_page(offset: usize, limit: usize) -> anyhow::Result<()> {
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        anyhow::bail!("limit must be between 1 and {MAX_PAGE_SIZE}");
    }
    offset
        .checked_add(limit)
        .context("offset plus limit is too large")?;
    Ok(())
}

fn validate_folder_options(folder: Option<&str>, folder_id: Option<&str>) -> anyhow::Result<()> {
    if folder.is_some() && folder_id.is_some() {
        anyhow::bail!("--folder and --folder-id cannot be used together");
    }
    if let Some(folder) = folder {
        validate_required_value(folder, "folder")?;
    }
    if let Some(folder_id) = folder_id {
        validate_required_value(folder_id, "folder ID")?;
    }
    Ok(())
}

fn validate_search(arguments: &MailSearchArgs) -> anyhow::Result<()> {
    validate_page(arguments.offset, arguments.limit)?;
    validate_folder_options(arguments.folder.as_deref(), arguments.folder_id.as_deref())?;
    if arguments
        .after
        .zip(arguments.before)
        .is_some_and(|(after, before)| after > before)
    {
        anyhow::bail!("--after cannot be later than --before");
    }
    match arguments.scope {
        SearchScope::AllFolders if arguments.folder.is_some() || arguments.folder_id.is_some() => {
            anyhow::bail!("--folder and --folder-id require --scope current-folder or subfolders");
        }
        _ => {}
    }
    let has_text = [
        arguments.query.as_deref(),
        arguments.subject.as_deref(),
        arguments.keywords.as_deref(),
        arguments.body.as_deref(),
        arguments.category.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty());
    let has_filter = has_text
        || !arguments.from.is_empty()
        || !arguments.to.is_empty()
        || !arguments.cc.is_empty()
        || !arguments.bcc.is_empty()
        || arguments.after.is_some()
        || arguments.before.is_some()
        || !matches!(arguments.read_status, SearchReadStatus::All)
        || arguments.has_attachments
        || arguments.flagged
        || !matches!(arguments.importance, SearchImportance::All)
        || arguments.mentions_me
        || arguments.to_me;
    if !has_filter {
        anyhow::bail!("search requires QUERY or at least one search filter");
    }
    Ok(())
}

fn build_search_query(arguments: &MailSearchArgs) -> anyhow::Result<String> {
    let mut recipient_clauses = Vec::new();
    push_recipient_clause(&mut recipient_clauses, "To", &arguments.to)?;
    push_recipient_clause(&mut recipient_clauses, "From", &arguments.from)?;
    push_recipient_clause(&mut recipient_clauses, "CC", &arguments.cc)?;
    push_recipient_clause(&mut recipient_clauses, "BCC", &arguments.bcc)?;

    let mut clauses = Vec::new();
    if !recipient_clauses.is_empty() {
        clauses.push(recipient_clauses.join(" AND "));
    }
    push_raw(&mut clauses, arguments.query.as_deref(), "query")?;
    push_raw(&mut clauses, arguments.keywords.as_deref(), "keywords")?;
    if let Some(subject) = validated_value(arguments.subject.as_deref(), "subject")? {
        clauses.push(format!("subject:({subject})"));
    }
    if let Some(body) = validated_value(arguments.body.as_deref(), "body")? {
        clauses.push(format!("body:({body})"));
    }
    if arguments.mentions_me {
        clauses.push("ismentioned:yes".to_string());
    }
    if arguments.to_me {
        clauses.push("to:me".to_string());
    }
    match arguments.read_status {
        SearchReadStatus::All => {}
        SearchReadStatus::Read => clauses.push("isread:yes".to_string()),
        SearchReadStatus::Unread => clauses.push("isread:no".to_string()),
    }
    if arguments.flagged {
        clauses.push("isflagged:yes".to_string());
    }
    match arguments.importance {
        SearchImportance::All => {}
        SearchImportance::High => clauses.push("importance:high".to_string()),
        SearchImportance::Normal => clauses.push("importance:normal".to_string()),
        SearchImportance::Low => clauses.push("importance:low".to_string()),
    }
    if arguments.has_attachments {
        clauses.push("hasattachments:yes".to_string());
    }
    if let Some(category) = validated_value(arguments.category.as_deref(), "category")? {
        clauses.push(format!("category:{}", quoted_query_value(category)));
    }
    let query = clauses.join(" ");
    if query.is_empty() && arguments.after.is_none() && arguments.before.is_none() {
        anyhow::bail!("search requires QUERY or at least one search filter");
    }
    Ok(query)
}

fn push_recipient_clause(
    clauses: &mut Vec<String>,
    field: &str,
    values: &[String],
) -> anyhow::Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    let values = values
        .iter()
        .map(|value| validate_required_value(value, field))
        .collect::<anyhow::Result<Vec<_>>>()?;
    clauses.push(format!("({field}:({}))", values.join(" OR ")));
    Ok(())
}

fn push_raw(clauses: &mut Vec<String>, value: Option<&str>, label: &str) -> anyhow::Result<()> {
    if let Some(value) = validated_value(value, label)? {
        clauses.push(value.to_string());
    }
    Ok(())
}

fn validated_value<'a>(value: Option<&'a str>, label: &str) -> anyhow::Result<Option<&'a str>> {
    value
        .map(|value| validate_required_value(value, label))
        .transpose()
}

fn validate_required_value<'a>(value: &'a str, label: &str) -> anyhow::Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{label} cannot be empty");
    }
    if value.chars().any(char::is_control) {
        anyhow::bail!("{label} cannot contain control characters");
    }
    Ok(value)
}

fn quoted_query_value(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn normalize_folders(response: &Value) -> anyhow::Result<MailFolderList> {
    let folders = startup_folders(response)?;
    let folders = folders
        .iter()
        .map(normalize_folder)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(MailFolderList {
        count: folders.len(),
        folders,
    })
}

fn normalize_folder(folder: &Value) -> anyhow::Result<MailFolderInfo> {
    Ok(MailFolderInfo {
        id: required_string_at(folder, "/FolderId/Id", "mail folder ID")?,
        change_key: string_at(folder, "/FolderId/ChangeKey"),
        distinguished_name: optional_string(folder, "DistinguishedFolderId"),
        name: optional_string(folder, "DisplayName").unwrap_or_else(|| "(unnamed)".to_string()),
        class: optional_string(folder, "FolderClass"),
        parent_id: string_at(folder, "/ParentFolderId/Id"),
        total_count: unsigned(folder, "TotalCount"),
        unread_count: unsigned(folder, "UnreadCount"),
        child_folder_count: unsigned(folder, "ChildFolderCount"),
    })
}

fn startup_folders(response: &Value) -> anyhow::Result<&[Value]> {
    response
        .pointer("/findFolders/Body/ResponseMessages/Items/0/RootFolder/Folders")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .context("OWA mail startup data has no folder list")
}

fn resolve_folder_id(response: &Value, requested: &str) -> anyhow::Result<String> {
    let requested = requested.trim();
    if requested.is_empty() {
        anyhow::bail!("folder cannot be empty");
    }
    let matches = startup_folders(response)?
        .iter()
        .filter(|folder| {
            optional_string(folder, "DistinguishedFolderId")
                .is_some_and(|name| name.eq_ignore_ascii_case(requested))
                || optional_string(folder, "DisplayName")
                    .is_some_and(|name| name.eq_ignore_ascii_case(requested))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [folder] => required_string_at(folder, "/FolderId/Id", "mail folder ID"),
        [] => anyhow::bail!(
            "mail folder `{requested}` was not found; run `outlook mail folders` to list folders"
        ),
        _ => anyhow::bail!(
            "mail folder name `{requested}` is ambiguous; use --folder-id from `outlook mail folders`"
        ),
    }
}

fn folder_and_descendant_ids(response: &Value, root_id: &str) -> anyhow::Result<Vec<String>> {
    if root_id.is_empty() {
        anyhow::bail!("mail search folder ID cannot be empty");
    }
    let folders = startup_folders(response)?;
    let mut included = HashSet::from([root_id.to_string()]);
    loop {
        let mut changed = false;
        for folder in folders {
            let Some(id) = string_at(folder, "/FolderId/Id") else {
                continue;
            };
            let Some(parent_id) = string_at(folder, "/ParentFolderId/Id") else {
                continue;
            };
            if included.contains(&parent_id) {
                changed |= included.insert(id);
            }
        }
        if !changed {
            break;
        }
    }
    let mut ids = vec![root_id.to_string()];
    ids.extend(folders.iter().filter_map(|folder| {
        let id = string_at(folder, "/FolderId/Id")?;
        (id != root_id && included.contains(&id)).then_some(id)
    }));
    Ok(ids)
}

fn distinguished_folder_name(value: &str) -> Option<&'static str> {
    let normalized = value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    match normalized.as_str() {
        "archive" => Some("archive"),
        "calendar" => Some("calendar"),
        "contacts" => Some("contacts"),
        "conversationhistory" => Some("conversationhistory"),
        "deleteditems" => Some("deleteditems"),
        "drafts" => Some("drafts"),
        "inbox" => Some("inbox"),
        "journal" => Some("journal"),
        "junkemail" => Some("junkemail"),
        "notes" => Some("notes"),
        "outbox" => Some("outbox"),
        "quickcontacts" => Some("quickcontacts"),
        "recipientcache" => Some("recipientcache"),
        "sentitems" => Some("sentitems"),
        "syncissues" => Some("syncissues"),
        "tasks" => Some("tasks"),
        _ => None,
    }
}

fn normalize_list(
    folder: Option<String>,
    folder_id: Option<String>,
    filter: MailViewFilter,
    offset: usize,
    response: &Value,
) -> anyhow::Result<MailList> {
    let root = find_item_root(response, "FindItem")?;
    let items = root
        .get("Items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let messages = items
        .iter()
        .map(normalize_summary)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let more = !root
        .get("IncludesLastItemInRange")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let next_offset = more.then(|| {
        root.get("IndexedPagingOffset")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or_else(|| offset.saturating_add(items.len()))
    });
    Ok(MailList {
        folder,
        folder_id,
        filter,
        offset,
        next_offset,
        total: root.get("TotalItemsInView").and_then(Value::as_u64),
        more,
        count: messages.len(),
        messages,
    })
}

fn normalize_message(response: &Value) -> anyhow::Result<MailMessage> {
    let response = response_message(response, "GetItem")?;
    let item = response
        .get("Items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .context("OWA GetItem response has no message")?;
    let body = item.get("NormalizedBody").map(|body| MailBody {
        content_type: optional_string(body, "BodyType").unwrap_or_else(|| "unknown".to_string()),
        truncated: boolean(body, "IsTruncated"),
        content: optional_string(body, "Value").unwrap_or_default(),
    });
    let attachments = item
        .get("Attachments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(normalize_attachment)
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(MailMessage {
        summary: normalize_summary(item)?,
        to: normalize_addresses(item.get("ToRecipients")),
        cc: normalize_addresses(item.get("CcRecipients")),
        bcc: normalize_addresses(item.get("BccRecipients")),
        received_representing: item.get("ReceivedRepresenting").and_then(normalize_address),
        internet_message_id: optional_string(item, "InternetMessageId"),
        body,
        attachments,
        has_blocked_images: boolean(item, "HasBlockedImages"),
    })
}

fn normalize_attachment(value: &Value) -> anyhow::Result<MailAttachment> {
    Ok(MailAttachment {
        id: required_string_at(value, "/AttachmentId/Id", "mail attachment ID")
            .or_else(|_| required_string(value, "AttachmentId", "mail attachment ID"))?,
        name: optional_string(value, "Name"),
        content_type: optional_string(value, "ContentType"),
        content_id: optional_string(value, "ContentId"),
        content_location: optional_string(value, "ContentLocation"),
        size: unsigned(value, "Size"),
        inline: boolean(value, "IsInline"),
        modified_at: optional_string(value, "LastModifiedTime"),
    })
}

fn normalize_search(
    query: String,
    scope: SearchScope,
    folder: Option<String>,
    folder_id: Option<String>,
    offset: usize,
    limit: usize,
    response: &Value,
) -> anyhow::Result<MailSearchResults> {
    let entity_sets = response
        .get("EntitySets")
        .and_then(Value::as_array)
        .context("mail search response has no EntitySets array")?;
    let mut total = None;
    let mut more = false;
    let mut partial = false;
    let mut results = Vec::new();
    for entity in entity_sets {
        partial |= boolean(entity, "IsPartial");
        for result_set in entity
            .get("ResultSets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            total = max_option(total, result_set.get("Total").and_then(Value::as_u64));
            more |= boolean(result_set, "MoreResultsAvailable");
            for result in result_set
                .get("Results")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                results.push(normalize_search_hit(result)?);
            }
        }
    }
    more |= results.len() > limit;
    results.truncate(limit);
    more &= !results.is_empty();
    let next_offset = more.then(|| offset.saturating_add(results.len()));
    let search_terms = response
        .get("SearchTerms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect();
    Ok(MailSearchResults {
        query,
        scope,
        folder,
        folder_id,
        offset,
        next_offset,
        total,
        more,
        partial,
        count: results.len(),
        search_terms,
        results,
    })
}

fn normalize_search_hit(result: &Value) -> anyhow::Result<MailSearchHit> {
    let source = result.get("Source").unwrap_or(result);
    let id = optional_string(source, "ImmutableId")
        .or_else(|| optional_string(source, "ItemId"))
        .or_else(|| string_at(source, "/ItemId/Id"))
        .context("mail search result has no immutable item ID")?;
    Ok(MailSearchHit {
        message: normalize_summary_with_id(source, id),
        rank: result.get("Rank").and_then(Value::as_f64),
        result_type: optional_string(result, "ResultSearchType"),
        content_source: optional_string(result, "ContentSource"),
        provider_type: optional_string(result, "ProviderType"),
        highlighted_summary: optional_string(result, "HitHighlightedSummary"),
    })
}

fn normalize_summary(value: &Value) -> anyhow::Result<MailMessageSummary> {
    let id = string_at(value, "/ItemId/Id")
        .or_else(|| optional_string(value, "ImmutableId"))
        .or_else(|| optional_string(value, "ItemId"))
        .context("mail item has no immutable item ID")?;
    Ok(normalize_summary_with_id(value, id))
}

fn normalize_summary_with_id(value: &Value, id: String) -> MailMessageSummary {
    let flag_status = value
        .get("Flag")
        .and_then(|flag| optional_string(flag, "FlagStatus"))
        .or_else(|| optional_string(value, "FlagStatus"));
    MailMessageSummary {
        id,
        change_key: string_at(value, "/ItemId/ChangeKey"),
        conversation_id: string_at(value, "/ConversationId/Id")
            .or_else(|| optional_string(value, "ConversationId")),
        subject: optional_string(value, "Subject").unwrap_or_else(|| "(no subject)".to_string()),
        preview: optional_string(value, "Preview"),
        from: value.get("From").and_then(normalize_address),
        sender: value.get("Sender").and_then(normalize_address),
        display_to: optional_string(value, "DisplayTo"),
        received_at: optional_string(value, "DateTimeReceived"),
        sent_at: optional_string(value, "DateTimeSent"),
        created_at: optional_string(value, "DateTimeCreated"),
        modified_at: optional_string(value, "LastModifiedTime")
            .or_else(|| optional_string(value, "DateTimeLastModified")),
        read: boolean(value, "IsRead"),
        draft: boolean(value, "IsDraft"),
        has_attachments: boolean(value, "HasAttachments"),
        flagged: flag_status.as_deref() == Some("Flagged") || boolean(value, "IsFlagged"),
        flag_status,
        importance: optional_string(value, "Importance"),
        sensitivity: optional_string(value, "Sensitivity"),
        item_class: optional_string(value, "ItemClass"),
        inference_classification: optional_string(value, "InferenceClassification"),
        size: unsigned(value, "Size"),
        parent_folder_id: string_at(value, "/ParentFolderId/Id")
            .or_else(|| optional_string(value, "ParentFolderId")),
        categories: strings(value, "Categories"),
    }
}

fn normalize_addresses(value: Option<&Value>) -> Vec<MailAddress> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(normalize_address)
        .collect()
}

fn normalize_address(value: &Value) -> Option<MailAddress> {
    if let Some(values) = value.as_array() {
        return values.first().and_then(normalize_address);
    }
    if let Some(value) = value.as_str() {
        return (!value.is_empty()).then(|| MailAddress {
            name: Some(value.to_string()),
            email: None,
        });
    }
    let mailbox = value.get("Mailbox").unwrap_or(value);
    let name = optional_string(mailbox, "Name").or_else(|| optional_string(mailbox, "DisplayName"));
    let email = optional_string(mailbox, "SmtpEmailAddress")
        .or_else(|| optional_string(mailbox, "EmailAddress"))
        .or_else(|| optional_string(mailbox, "Address"));
    (name.is_some() || email.is_some()).then_some(MailAddress { name, email })
}

fn find_item_root<'a>(response: &'a Value, action: &str) -> anyhow::Result<&'a Value> {
    response_message(response, action)?
        .get("RootFolder")
        .with_context(|| format!("OWA {action} response has no RootFolder"))
}

fn validate_mail_response(response: &Value, action: &str) -> anyhow::Result<()> {
    response_message(response, action).map(|_| ())
}

fn response_message<'a>(response: &'a Value, action: &str) -> anyhow::Result<&'a Value> {
    let message = response
        .pointer("/Body/ResponseMessages/Items/0")
        .with_context(|| format!("OWA {action} response has no response message"))?;
    let class = message
        .get("ResponseClass")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let code = message
        .get("ResponseCode")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if class != "Success" || code != "NoError" {
        anyhow::bail!("OWA {action} failed: class={class}, code={code}");
    }
    Ok(message)
}

fn required_string_at(value: &Value, pointer: &str, label: &str) -> anyhow::Result<String> {
    string_at(value, pointer).with_context(|| format!("{label} is missing"))
}

fn required_string(value: &Value, key: &str, label: &str) -> anyhow::Result<String> {
    optional_string(value, key).with_context(|| format!("{label} is missing"))
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
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn boolean(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn unsigned(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn max_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MailSearchArgs, MailViewFilter, SearchImportance, SearchReadStatus, SearchScope,
        build_search_query, folder_and_descendant_ids, normalize_list, normalize_message,
        normalize_search, normalize_search_hit, resolve_folder_id, validate_mail_response,
    };
    use chrono::NaiveDate;
    use serde_json::json;

    fn search_arguments() -> MailSearchArgs {
        MailSearchArgs {
            query: Some("release".into()),
            scope: SearchScope::AllFolders,
            folder: None,
            folder_id: None,
            from: vec!["sender@example.com".into()],
            to: vec!["recipient@example.com".into()],
            cc: vec![],
            bcc: vec![],
            subject: Some("deployment".into()),
            keywords: None,
            body: Some("success".into()),
            after: Some(NaiveDate::from_ymd_opt(2026, 7, 1).unwrap()),
            before: Some(NaiveDate::from_ymd_opt(2026, 7, 18).unwrap()),
            read_status: SearchReadStatus::Unread,
            has_attachments: true,
            flagged: true,
            importance: SearchImportance::High,
            category: Some("Red category".into()),
            mentions_me: true,
            to_me: true,
            offset: 0,
            limit: 25,
            raw: false,
        }
    }

    #[test]
    fn rejects_owa_application_errors_before_raw_output() {
        let response = json!({
            "Body": {"ResponseMessages": {"Items": [{
                "ResponseClass": "Error",
                "ResponseCode": "ErrorInvalidIdMalformed",
                "MessageText": "sensitive server detail"
            }]}}
        });
        let error = validate_mail_response(&response, "GetItem")
            .unwrap_err()
            .to_string();
        assert!(error.contains("class=Error"));
        assert!(error.contains("code=ErrorInvalidIdMalformed"));
        assert!(!error.contains("sensitive server detail"));
    }

    #[test]
    fn search_results_require_exchange_item_ids() {
        let result = json!({
            "Id": "provider-result-id",
            "Source": {"Subject": "Subject"}
        });
        assert!(normalize_search_hit(&result).is_err());
    }

    #[test]
    fn list_filters_match_observed_owa_view_filters() {
        for (filter, expected) in [
            (MailViewFilter::All, "All"),
            (MailViewFilter::Unread, "Unread"),
            (MailViewFilter::Flagged, "Flagged"),
            (MailViewFilter::ToMe, "ToOrCcMe"),
            (MailViewFilter::HasFiles, "HasFile"),
            (MailViewFilter::MentionsMe, "Mentioned"),
            (MailViewFilter::HasCalendarInvites, "HasCalendarInvite"),
        ] {
            assert_eq!(filter.wire_name(), expected);
        }
    }

    #[test]
    fn builds_all_observed_search_filters() {
        let query = build_search_query(&search_arguments()).unwrap();
        for expected in [
            "(To:(recipient@example.com))",
            "(From:(sender@example.com))",
            "subject:(deployment)",
            "release",
            "body:(success)",
            "ismentioned:yes",
            "to:me",
            "isread:no",
            "isflagged:yes",
            "importance:high",
            "hasattachments:yes",
            "category:\"Red category\"",
        ] {
            assert!(query.contains(expected), "missing {expected} in {query}");
        }
    }

    #[test]
    fn normalizes_mail_list_and_pagination() {
        let response = json!({
            "Body": {"ResponseMessages": {"Items": [{
                "ResponseClass": "Success",
                "ResponseCode": "NoError",
                "RootFolder": {
                    "TotalItemsInView": 10,
                    "IndexedPagingOffset": 3,
                    "IncludesLastItemInRange": false,
                    "Items": [{
                        "ItemId": {"Id": "message-id", "ChangeKey": "change"},
                        "ConversationId": {"Id": "conversation"},
                        "Subject": "Subject",
                        "Preview": "Preview",
                        "From": {"Mailbox": {"Name": "Sender", "EmailAddress": "sender@example.com"}},
                        "DateTimeReceived": "2026-07-18T12:00:00Z",
                        "IsRead": true,
                        "HasAttachments": true,
                        "Flag": {"FlagStatus": "Flagged"},
                        "Size": 42
                    }]
                }
            }]}}
        });
        let list = normalize_list(
            Some("inbox".into()),
            None,
            MailViewFilter::All,
            2,
            &response,
        )
        .unwrap();
        assert_eq!(list.count, 1);
        assert_eq!(list.next_offset, Some(3));
        assert!(list.messages[0].read);
        assert!(list.messages[0].flagged);
        assert_eq!(list.messages[0].id, "message-id");
    }

    #[test]
    fn normalizes_message_body_recipients_and_attachments() {
        let response = json!({
            "Body": {"ResponseMessages": {"Items": [{
                "ResponseClass": "Success",
                "ResponseCode": "NoError",
                "Items": [{
                    "ItemId": {"Id": "message-id"},
                    "Subject": "Subject",
                    "ToRecipients": [{"Mailbox": {"Name": "Person", "EmailAddress": "person@example.com"}}],
                    "NormalizedBody": {"IsTruncated": false, "Value": "<p>Hello</p>"},
                    "Attachments": [{
                        "AttachmentId": {"Id": "attachment-id"},
                        "Name": "file.txt",
                        "ContentType": "text/plain",
                        "Size": 5,
                        "IsInline": false
                    }]
                }]
            }]}}
        });
        let message = normalize_message(&response).unwrap();
        assert_eq!(message.to.len(), 1);
        let body = message.body.unwrap();
        assert_eq!(body.content_type, "unknown");
        assert_eq!(body.content, "<p>Hello</p>");
        assert_eq!(message.attachments[0].id, "attachment-id");
    }

    #[test]
    fn normalizes_search_results_using_immutable_ids() {
        let response = json!({
            "SearchTerms": ["release"],
            "EntitySets": [{
                "IsPartial": false,
                "ResultSets": [{
                    "Total": 2,
                    "MoreResultsAvailable": false,
                    "Results": [
                        {
                            "Rank": 1,
                            "ResultSearchType": "TopResult",
                            "ContentSource": "Exchange",
                            "HitHighlightedSummary": "match",
                            "Source": {
                                "ImmutableId": "immutable-id",
                                "Subject": "Subject",
                                "Preview": "Preview",
                                "IsRead": false
                            }
                        },
                        {
                            "Rank": 2,
                            "Source": {
                                "ImmutableId": "second-id",
                                "Subject": "Second"
                            }
                        }
                    ]
                }]
            }]
        });
        let search = normalize_search(
            "release".into(),
            SearchScope::AllFolders,
            None,
            None,
            0,
            1,
            &response,
        )
        .unwrap();
        assert_eq!(search.count, 1);
        assert_eq!(search.next_offset, Some(1));
        assert_eq!(search.results[0].message.id, "immutable-id");
    }

    #[test]
    fn expands_subfolder_scope_from_startup_tree() {
        let response = json!({
            "findFolders": {"Body": {"ResponseMessages": {"Items": [{
                "RootFolder": {"Folders": [
                    {"FolderId": {"Id": "child"}, "ParentFolderId": {"Id": "root"}},
                    {"FolderId": {"Id": "grandchild"}, "ParentFolderId": {"Id": "child"}},
                    {"FolderId": {"Id": "other"}, "ParentFolderId": {"Id": "elsewhere"}}
                ]}
            }]}}}
        });
        assert_eq!(
            folder_and_descendant_ids(&response, "root").unwrap(),
            ["root", "child", "grandchild"]
        );
    }

    #[test]
    fn resolves_custom_folder_display_names() {
        let response = json!({
            "findFolders": {"Body": {"ResponseMessages": {"Items": [{
                "RootFolder": {"Folders": [{
                    "DisplayName": "Custom Folder",
                    "FolderId": {"Id": "folder-id"}
                }]}
            }]}}}
        });
        assert_eq!(
            resolve_folder_id(&response, "custom folder").unwrap(),
            "folder-id"
        );
    }
}

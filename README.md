<div align="center">
  <img src="assets/logo.png" alt="outlook-cli logo" width="160">
  <h1>outlook-cli</h1>
  <p><em>An unofficial command-line tool for reading Outlook Web calendar and mail.</em></p>
</div>

---

`outlook` talks to Outlook's private OWA/Exchange APIs so you can read calendar
events and mail from the terminal. Output is JSON, so it pipes cleanly into
`jq`.

> [!WARNING]
> **Unofficial and unaffiliated.** This project is not associated with Microsoft.
> It calls private, undocumented APIs that can change without notice and may be
> subject to your organization's acceptable-use policies. Use it at your own risk.

## Install

```bash
cargo install --path . --locked
```

## Usage

```console
$ outlook --help
Query Outlook Web calendar and mail from the terminal

Usage: outlook <COMMAND>

Commands:
  auth         Authentication and token lifecycle
  config       Read or update local configuration
  calendar     Calendar queries
  mail         Mailbox folders, messages, and search
  completions  Generate shell completions
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Run `outlook <command> --help` for a group's subcommands.

## Setup

```bash
outlook config set username person@example.com
outlook config set password
outlook config set authenticator-key
outlook auth login
```

The password and authenticator-key commands prompt without echoing input. The
authenticator key may be a base32 secret or an `otpauth://` URI. Credential login
supports Authenticator TOTP and uses Chrome or Chromium, discovered from `PATH`
by default.

## Mail

```bash
outlook mail folders
outlook mail list --folder inbox
outlook mail list --filter unread --limit 10
outlook mail get '<immutable-item-id>'
outlook mail search GitHub
```

Folder-list filters mirror Outlook's Filter menu:

```text
all  unread  flagged  to-me  has-files  mentions-me  has-calendar-invites
```

Full search supports Outlook's advanced filters and searches Exchange plus the
online archive:

```bash
outlook mail search --from sender@example.com --read-status unread
outlook mail search --subject deploy --has-attachments --importance high
outlook mail search --body failure --after 2026-07-01 --before 2026-07-31
outlook mail search --to-me --mentions-me --flagged
outlook mail search release --scope current-folder --folder 'Sent Items'
outlook mail search release --scope subfolders --folder Projects
```

Available search fields are `--from`, `--to`, `--cc`, `--bcc`, `--subject`,
`--keywords`, `--body`, `--after`, `--before`, `--read-status`,
`--has-attachments`, `--flagged`, `--importance`, `--category`, `--mentions-me`,
and `--to-me`. Recipient options may be repeated. Use `--offset` with
`--limit` (maximum 50) for pagination. The positional query also accepts an
Outlook search expression.

Message IDs are immutable Exchange IDs. Pass an ID returned by `list` or
`search` to `mail get`. Add `--raw` to any mail query to inspect its underlying
private API response data.

## Calendar

```bash
outlook calendar list --week current
outlook calendar list --week next | jq '.events[] | {start, subject, organizer}'
outlook calendar list --week last --raw
```

Weeks run Sunday through Saturday. The timezone defaults from the operating
system and can be overridden with:

```bash
outlook config set timezone 'Eastern Standard Time'
```

## Notes

- Authentication automatically tries the cached access token, refresh token,
  persistent Microsoft session, and finally headless username/password/TOTP login.
- `outlook auth logout` clears only the CLI's authentication state; configured
  credentials are preserved.
- Configuration, tokens, cookies, and credentials are stored in plaintext at
  `~/.config/outlook-cli/session.json`. The directory and file use owner-only
  permissions, and the file is replaced atomically.
- `outlook config get` redacts secrets unless `--show-secrets` is supplied.

## License

[MIT](LICENSE)

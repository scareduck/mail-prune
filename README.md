# mail-prune

`mail-prune.py` supports pruning one or many IMAP accounts in a single run.

## Config formats

### Legacy single-account config (still supported)

```yaml
account:
  username: me@example.com
  credentials_key: me@example.com
  credentials_json: ~/.config/mail-prune/creds.json
  host: imap.example.com
  mailbox: INBOX
  action: copy_to_folder
  target_mailbox: PurgeQueue

rules:
  - name: old-newsletters
    days: 14
    from_regex: "newsletter@"
```

### Multi-account config

```yaml
accounts:
  - username: me@example.com
    credentials_key: me@example.com
    credentials_json: ~/.config/mail-prune/creds.json
    host: imap.example.com
    mailbox: INBOX
    action: copy_to_folder
    target_mailbox: PurgeQueue

  - username: alerts@example.net
    credentials_key: alerts@example.net
    credentials_json: ~/.config/mail-prune/creds.json
    host: imap.example.net
    mailbox: Alerts
    action: copy_to_trash
    trash_mailbox: Trash

rules:
  global:
    - name: old-newsletters
      days: 14
      from_regex: "newsletter@"

  per_address:
    me@example.com:
      - name: repo-notifications
        days: 7
        subject_regex: "\\[repo\\]"

    alerts@example.net:
      - name: old-alerts
        days: 2
        from_regex: "alerts@"
```

`rules.global` applies to every account. `rules.per_address.<username-email>` applies only to that account.

## Multi-account behavior notes

- Best effort: one account failure does not abort other accounts.
- If an account resolves to zero rules, it is skipped with a warning.
- Notifications are consolidated into a single run-level message.
- Cache rows are synced each run: `msg_cache` rows for UIDs no longer in the mailbox are pruned.

## CLI account/mailbox selection behavior

- `--address <email>` limits processing to a single configured account whose `username` matches that address.
- `--mailbox <name>` can be repeated and overrides configured default mailbox selection.
- If `--mailbox` is provided, `--ignore-age` defaults to enabled (archival-folder behavior).
- Use `--noignore-age` to force TTL mode even when `--mailbox` is specified.

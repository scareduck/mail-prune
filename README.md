# mail-prune

`mail-prune.py` now supports pruning one or many IMAP accounts in a single run.

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

`rules.global` applies to every account. `rules.per_address.<email>` applies only to that email/account.

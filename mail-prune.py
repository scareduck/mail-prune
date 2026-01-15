#!/usr/bin/python3

r"""
mail-prune.py — safety-first IMAP hygiene tool
(single SQLite connection + dead-man staleness + dry-run safe queueing)

Safety:
- Only uses UID COPY to a destination mailbox (PurgeQueue by default, or Trash if configured).

Modes:
- TTL mode (default): incremental UID ingest (headers-only) + local matching from SQLite cache.
- --ignore-age mode: one-time sweep of a mailbox (UID SEARCH ALL + chunked UID FETCH),
  apply all rules per msg locally, first match wins.
  Dead-man staleness is DISABLED in --ignore-age mode.

Dead-man staleness semantics (stale_after_days):
- Tracks when we last *SAW* a matching message for a rule (based on headers),
  independent of TTL eligibility (rule.days).
- In TTL mode, we mark "seen" as soon as a message matches a rule’s header filters,
  even if it's too new to be queued.

Dry-run semantics:
- Dry-run NEVER poisons the queued table.
- queued is only written when a real COPY happens.
"""

from __future__ import annotations

import argparse
import email
import imaplib
import json
import os
import re
import sqlite3
import ssl
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.message import EmailMessage
from typing import Dict, Iterable, List, Optional, Tuple

import smtplib


# -----------------------------
# Utility
# -----------------------------

def expand_path(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p)) if isinstance(p, str) else p


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def decode_mime_header(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def chunks(seq: List[int], n: int) -> Iterable[List[int]]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# -----------------------------
# Config
# -----------------------------

def load_yaml_config(path: str) -> dict:
    import yaml  # python3-pyyaml
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg if isinstance(cfg, dict) else {}


# -----------------------------
# Credentials (your JSON format)
# -----------------------------

def load_creds(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def get_password(creds: dict, email_key: str, field: str = "password") -> str:
    """
    Supports:
      1) { "<email>": { "password": "...", "smtp_password": "..." } }
      2) { "accounts": { "<email>": { ... } } }
    """
    root = creds.get("accounts")
    if isinstance(root, dict):
        entry = root.get(email_key, {})
    else:
        entry = creds.get(email_key, {})

    if not isinstance(entry, dict):
        return ""

    val = entry.get(field)
    if isinstance(val, str) and val:
        return val

    # fallback for smtp_password -> password
    if field != "password":
        val2 = entry.get("password")
        if isinstance(val2, str) and val2:
            return val2

    return ""


# -----------------------------
# SQLite (single-connection design)
# -----------------------------

def db_init(db_path: str) -> None:
    db_path = expand_path(db_path)
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            account TEXT NOT NULL,
            mailbox TEXT NOT NULL,
            uidvalidity INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            message_id TEXT,
            internaldate TEXT,
            date_hdr TEXT,
            from_raw TEXT,
            subject TEXT,
            list_id TEXT,
            list_unsubscribe TEXT,
            rule_name TEXT,
            action TEXT NOT NULL,
            dest_mailbox TEXT
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_rule_ts ON actions(rule_name, ts);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions(ts);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_uid ON actions(account, mailbox, uidvalidity, uid);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS mailbox_state (
            account TEXT NOT NULL,
            mailbox TEXT NOT NULL,
            uidvalidity INTEGER NOT NULL,
            last_seen_uid INTEGER NOT NULL DEFAULT 0,
            last_run_ts TEXT,
            PRIMARY KEY (account, mailbox, uidvalidity)
        );
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS msg_cache (
            account TEXT NOT NULL,
            mailbox TEXT NOT NULL,
            uidvalidity INTEGER NOT NULL,
            uid INTEGER NOT NULL,

            internaldate TEXT,
            date_hdr TEXT,
            message_id TEXT,
            from_raw TEXT,
            subject TEXT,
            list_id TEXT,
            list_unsubscribe TEXT,

            first_seen_ts TEXT NOT NULL,
            last_seen_ts TEXT NOT NULL,

            PRIMARY KEY (account, mailbox, uidvalidity, uid)
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_internaldate ON msg_cache(account, mailbox, internaldate);")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS queued (
            account TEXT NOT NULL,
            mailbox TEXT NOT NULL,
            uidvalidity INTEGER NOT NULL,
            uid INTEGER NOT NULL,
            dest_mailbox TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            queued_ts TEXT NOT NULL,
            PRIMARY KEY (account, mailbox, uidvalidity, uid, dest_mailbox, rule_name)
        );
        """)

        # Dead-man switch state: last time we SAW any message matching a rule (headers match)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_state (
            account TEXT NOT NULL,
            mailbox TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            last_seen_match_ts TEXT,
            PRIMARY KEY (account, mailbox, rule_name)
        );
        """)


def db_set_state(conn: sqlite3.Connection, account: str, mailbox: str, uidvalidity: int, last_seen_uid: int) -> None:
    conn.execute("""
    INSERT INTO mailbox_state(account, mailbox, uidvalidity, last_seen_uid, last_run_ts)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(account, mailbox, uidvalidity)
    DO UPDATE SET last_seen_uid=excluded.last_seen_uid, last_run_ts=excluded.last_run_ts
    """, (account, mailbox, uidvalidity, int(last_seen_uid), utc_now().isoformat()))


def db_get_state(conn: sqlite3.Connection, account: str, mailbox: str, uidvalidity: int) -> int:
    row = conn.execute("""
        SELECT last_seen_uid FROM mailbox_state
        WHERE account=? AND mailbox=? AND uidvalidity=?
    """, (account, mailbox, uidvalidity)).fetchone()
    return int(row[0]) if row else 0


def db_upsert_cache(conn: sqlite3.Connection, account: str, mailbox: str, uidvalidity: int, uid: int, hdr: dict) -> None:
    now = utc_now().isoformat()
    conn.execute("""
    INSERT INTO msg_cache(
        account, mailbox, uidvalidity, uid,
        internaldate, date_hdr, message_id, from_raw, subject, list_id, list_unsubscribe,
        first_seen_ts, last_seen_ts
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(account, mailbox, uidvalidity, uid)
    DO UPDATE SET
        internaldate=excluded.internaldate,
        date_hdr=excluded.date_hdr,
        message_id=excluded.message_id,
        from_raw=excluded.from_raw,
        subject=excluded.subject,
        list_id=excluded.list_id,
        list_unsubscribe=excluded.list_unsubscribe,
        last_seen_ts=excluded.last_seen_ts
    """, (
        account, mailbox, uidvalidity, int(uid),
        hdr.get("internaldate"),
        hdr.get("date_hdr"),
        hdr.get("message_id"),
        hdr.get("from_raw"),
        hdr.get("subject"),
        hdr.get("list_id"),
        hdr.get("list_unsubscribe"),
        now, now
    ))


def db_is_queued(conn: sqlite3.Connection, account: str, mailbox: str, uidvalidity: int, uid: int, dest: str, rule: str) -> bool:
    row = conn.execute("""
        SELECT 1 FROM queued
        WHERE account=? AND mailbox=? AND uidvalidity=? AND uid=? AND dest_mailbox=? AND rule_name=?
    """, (account, mailbox, uidvalidity, int(uid), dest, rule)).fetchone()
    return bool(row)


def db_mark_queued(conn: sqlite3.Connection, account: str, mailbox: str, uidvalidity: int, uid: int, dest: str, rule: str) -> None:
    conn.execute("""
    INSERT OR IGNORE INTO queued(account, mailbox, uidvalidity, uid, dest_mailbox, rule_name, queued_ts)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (account, mailbox, uidvalidity, int(uid), dest, rule, utc_now().isoformat()))


def db_log_action(conn: sqlite3.Connection, row: dict) -> None:
    conn.execute("""
    INSERT INTO actions(
        ts, account, mailbox, uidvalidity, uid,
        message_id, internaldate, date_hdr,
        from_raw, subject, list_id, list_unsubscribe,
        rule_name, action, dest_mailbox
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        row["ts"], row["account"], row["mailbox"], int(row["uidvalidity"]), int(row["uid"]),
        row.get("message_id"), row.get("internaldate"), row.get("date_hdr"),
        row.get("from_raw"), row.get("subject"), row.get("list_id"), row.get("list_unsubscribe"),
        row.get("rule_name"), row.get("action"), row.get("dest_mailbox")
    ))


def db_mark_rule_seen(conn: sqlite3.Connection, account: str, mailbox: str, rule_name: str, ts: str) -> None:
    """Dead-man switch: record that we have SEEN a message matching rule_name recently."""
    conn.execute("""
    INSERT INTO rule_state(account, mailbox, rule_name, last_seen_match_ts)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(account, mailbox, rule_name)
    DO UPDATE SET last_seen_match_ts=excluded.last_seen_match_ts
    """, (account, mailbox, rule_name, ts))


def stale_rule_warnings_deadman(conn: sqlite3.Connection, raw_rules: list, now: datetime,
                                account: str, mailboxes: List[str]) -> List[str]:
    """Warn if we haven't SEEN a match for a rule in stale_after_days (dead-man switch)."""
    thresholds: Dict[str, int] = {}
    for r in raw_rules:
        sad = r.get("stale_after_days")
        if sad is not None:
            thresholds[r["name"]] = int(sad)
    if not thresholds:
        return []

    placeholders = ",".join("?" for _ in mailboxes)
    q = f"""
        SELECT rule_name, mailbox, last_seen_match_ts
        FROM rule_state
        WHERE account=? AND mailbox IN ({placeholders})
    """
    rows = conn.execute(q, [account, *mailboxes]).fetchall()

    # last-seen per rule across scanned mailboxes
    last_seen: Dict[str, datetime] = {}
    for rn, mb, ts in rows:
        if rn and ts:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            cur = last_seen.get(rn)
            if cur is None or dt > cur:
                last_seen[rn] = dt

    warnings: List[str] = []
    for name, threshold in thresholds.items():
        last = last_seen.get(name)
        if not last:
            warnings.append(f"WARN {name}: never seen a matching message yet (threshold={threshold}d)")
            continue
        age_days = int((now - last).total_seconds() // 86400)
        if age_days > threshold:
            warnings.append(f"WARN {name}: last seen match {last.date().isoformat()} ({age_days}d ago) threshold={threshold}d")
    return warnings


# -----------------------------
# SMTP notify
# -----------------------------

def send_smtp_email(host: str, port: int, starttls: bool,
                    username: str, password: str,
                    to_addr: str, from_addr: str,
                    subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["To"] = to_addr
    msg["From"] = from_addr
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=30) as s:
        s.ehlo()
        if starttls:
            s.starttls()
            s.ehlo()
        if username:
            s.login(username, password)
        s.send_message(msg)


# -----------------------------
# Rules
# -----------------------------

@dataclass
class Rule:
    name: str
    days: int
    from_rx: Optional[re.Pattern]
    subject_rx: Optional[re.Pattern]
    match_mode: str  # "any" (OR) or "all" (AND among defined fields)


def compile_rules(raw_rules: list) -> List[Rule]:
    out: List[Rule] = []
    for r in raw_rules:
        mode = (r.get("match") or "any").strip().lower()
        if mode not in ("any", "all"):
            raise ValueError(f'Rule "{r.get("name","<unnamed>")}": match must be "any" or "all" (got {mode!r})')

        out.append(Rule(
            name=r["name"],
            days=int(r.get("days", 0)),
            from_rx=re.compile(r["from_regex"], re.IGNORECASE) if r.get("from_regex") else None,
            subject_rx=re.compile(r["subject_regex"], re.IGNORECASE) if r.get("subject_regex") else None,
            match_mode=mode,
        ))
    return out


def rule_matches(rule: Rule, frm: str, subj: str) -> bool:
    from_ok = bool(rule.from_rx.search(frm)) if rule.from_rx else False
    subj_ok = bool(rule.subject_rx.search(subj)) if rule.subject_rx else False

    if rule.match_mode == "all":
        checks: List[bool] = []
        if rule.from_rx:
            checks.append(from_ok)
        if rule.subject_rx:
            checks.append(subj_ok)
        return bool(checks) and all(checks)

    return from_ok or subj_ok


# -----------------------------
# IMAP
# -----------------------------

def connect_imap(host: str, port: int, starttls: bool) -> imaplib.IMAP4:
    if port == 993:
        ctx = ssl.create_default_context()
        return imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    imap = imaplib.IMAP4(host, port)
    if starttls:
        imap.starttls()
    return imap


def login_imap(imap: imaplib.IMAP4, username: str, password: str) -> None:
    typ, data = imap.login(username, password)
    if typ != "OK":
        raise RuntimeError(f"IMAP login failed: {data}")


def select_mailbox(imap: imaplib.IMAP4, mailbox: str) -> None:
    typ, data = imap.select(mailbox)
    if typ != "OK":
        raise RuntimeError(f"Cannot select mailbox {mailbox}: {data}")


def ensure_mailbox_exists(imap: imaplib.IMAP4, mailbox: str) -> None:
    try:
        imap.create(mailbox)
    except Exception:
        pass


def status_uidvalidity_uidnext(imap: imaplib.IMAP4, mailbox: str) -> Tuple[int, int]:
    typ, data = imap.status(mailbox, "(UIDVALIDITY UIDNEXT)")
    if typ != "OK" or not data or not data[0]:
        raise RuntimeError(f"STATUS failed for {mailbox}: {data}")
    s = data[0].decode(errors="ignore")
    m1 = re.search(r"UIDVALIDITY\s+(\d+)", s)
    m2 = re.search(r"UIDNEXT\s+(\d+)", s)
    if not m1 or not m2:
        raise RuntimeError(f"Could not parse STATUS response: {s}")
    return int(m1.group(1)), int(m2.group(1))


def uid_search_all(imap: imaplib.IMAP4) -> List[int]:
    typ, data = imap.uid("SEARCH", None, "ALL")
    if typ != "OK":
        raise RuntimeError(f"UID SEARCH ALL failed: {data}")
    if not data or not data[0]:
        return []
    return [int(x) for x in data[0].split()]


def uid_fetch_headers(imap: imaplib.IMAP4, uids: List[int]) -> Dict[int, dict]:
    if not uids:
        return {}

    fields = "FROM SUBJECT DATE MESSAGE-ID LIST-ID LIST-UNSUBSCRIBE"
    uidset = ",".join(str(u) for u in uids)

    typ, data = imap.uid("FETCH", uidset, f"(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS ({fields})])")
    if typ != "OK":
        raise RuntimeError(f"UID FETCH failed: {data}")

    out: Dict[int, dict] = {}

    for item in data:
        if not item or item == b")":
            continue
        if not isinstance(item, tuple) or len(item) < 2:
            continue

        meta = item[0].decode(errors="ignore")
        raw_hdr = item[1]

        m_uid = re.search(r"\bUID\s+(\d+)\b", meta)
        m_idate = re.search(r'INTERNALDATE\s+"([^"]+)"', meta)
        if not m_uid:
            continue
        uid = int(m_uid.group(1))
        internaldate = m_idate.group(1) if m_idate else None

        msg = email.message_from_bytes(raw_hdr)
        out[uid] = {
            "internaldate": internaldate,
            "date_hdr": decode_mime_header(msg.get("Date", "")),
            "message_id": decode_mime_header(msg.get("Message-ID", "")),
            "from_raw": decode_mime_header(msg.get("From", "")),
            "subject": decode_mime_header(msg.get("Subject", "")),
            "list_id": decode_mime_header(msg.get("List-ID", "")),
            "list_unsubscribe": decode_mime_header(msg.get("List-Unsubscribe", "")),
        }

    return out


def uid_copy(imap: imaplib.IMAP4, uid: int, dest_mailbox: str) -> None:
    typ, data = imap.uid("COPY", str(uid), dest_mailbox)
    if typ != "OK":
        raise RuntimeError(f"UID COPY to {dest_mailbox} failed: {data}")

def uid_mark_deleted(imap: imaplib.IMAP4, uid: int) -> None:
    typ, data = imap.uid("STORE", str(uid), "+FLAGS.SILENT", r"(\Deleted)")
    if typ != "OK":
        raise RuntimeError(f"UID STORE +FLAGS \\Deleted failed: {data}")

# -----------------------------
# TTL decision helpers
# -----------------------------

def parse_internaldate_to_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%d-%b-%Y %H:%M:%S %z")
    except Exception:
        return None


def eligible_by_days(internal_dt: Optional[datetime], now: datetime, days: int) -> bool:
    if days <= 0:
        return True
    if not internal_dt:
        return False
    return internal_dt < (now - timedelta(days=days))


def min_rule_days(rules: List[Rule]) -> int:
    ds = [r.days for r in rules if r.days and r.days > 0]
    return min(ds) if ds else 0


# -----------------------------
# Core engines
# -----------------------------

def ingest_new_headers_ttl(conn: sqlite3.Connection, imap: imaplib.IMAP4,
                           account: str, mailbox: str,
                           uidvalidity: int, uidnext: int,
                           verbose: bool) -> int:
    last_seen = db_get_state(conn, account, mailbox, uidvalidity)
    start_uid = last_seen + 1
    end_uid = uidnext - 1

    if end_uid < start_uid:
        if verbose:
            print(f"[{mailbox}] ingest: no new UIDs (last_seen={last_seen}, uidnext={uidnext})")
        db_set_state(conn, account, mailbox, uidvalidity, last_seen)
        return 0

    new_uids = list(range(start_uid, end_uid + 1))
    ingested = 0

    for part in chunks(new_uids, 200):
        hdrs = uid_fetch_headers(imap, part)
        for uid, h in hdrs.items():
            db_upsert_cache(conn, account, mailbox, uidvalidity, uid, h)
            ingested += 1

    db_set_state(conn, account, mailbox, uidvalidity, end_uid)

    if verbose:
        print(f"[{mailbox}] ingest: {ingested} new messages cached (UID {start_uid}..{end_uid})")

    return ingested


def ttl_process_from_cache(conn: sqlite3.Connection, imap: imaplib.IMAP4,
                           account: str, mailbox: str,
                           uidvalidity: int,
                           rules: List[Rule],
                           dest_mailbox: str,
                           dry_run: bool,
                           verbose: bool,
                           max_per_rule: int,
                           delete_from_source: bool) -> Tuple[int, int, int]:
    now = utc_now()

    rows = conn.execute("""
        SELECT uid, internaldate, from_raw, subject, date_hdr, message_id, list_id, list_unsubscribe
        FROM msg_cache
        WHERE account=? AND mailbox=? AND uidvalidity=?
    """, (account, mailbox, uidvalidity)).fetchall()

    candidates = 0
    matched = 0
    copied = 0
    per_rule_counts: Dict[str, int] = {r.name: 0 for r in rules}

    for (uid, internal_s, frm, subj, date_hdr, message_id, list_id, list_unsub) in rows:
        #if "codex" in (subj or "").lower() or "astral" in (frm or "").lower():
        #    print("DEBUG ACT CANDIDATE:", frm, " // ", subj)

        internal_dt = parse_internaldate_to_dt(internal_s)
        
        candidates += 1

        # Find first matching rule by headers (independent of TTL)
        winner: Optional[Rule] = None
        for r in rules:
            if rule_matches(r, frm or "", subj or ""):
                winner = r
                break

        if not winner:
            continue

        # Dead-man switch: record "seen" regardless of age
        db_mark_rule_seen(conn, account, mailbox, winner.name, utc_now().isoformat())

        # TTL gating: only act once old enough
        if not eligible_by_days(internal_dt, now, winner.days):
            continue

        matched += 1

        if max_per_rule and per_rule_counts[winner.name] >= max_per_rule:
            continue

        if db_is_queued(conn, account, mailbox, uidvalidity, int(uid), dest_mailbox, winner.name):
            continue

        line = f'[{mailbox}] [{winner.name}] UID={uid} From="{frm}" Subject="{subj}" -> {dest_mailbox} (COPY)'

        if dry_run:
            if verbose:
                print("DRY-RUN:", line)
            action_taken = "dry_run"
        else:
            uid_copy(imap, int(uid), dest_mailbox)
            if delete_from_source:
                uid_mark_deleted(imap, int(uid))
                action_taken = "copied_deleted"
            else:
                action_taken = "copied"
            copied += 1
            if verbose:
                print("OK:", line)
            # Only mark queued if we actually copied
            db_mark_queued(conn, account, mailbox, uidvalidity, int(uid), dest_mailbox, winner.name)

        # Always log
        db_log_action(conn, {
            "ts": utc_now().isoformat(),
            "account": account,
            "mailbox": mailbox,
            "uidvalidity": uidvalidity,
            "uid": int(uid),
            "message_id": message_id,
            "internaldate": internal_s,
            "date_hdr": date_hdr,
            "from_raw": frm,
            "subject": subj,
            "list_id": list_id,
            "list_unsubscribe": list_unsub,
            "rule_name": winner.name,
            "action": action_taken,
            "dest_mailbox": dest_mailbox,
        })
        per_rule_counts[winner.name] += 1

    if verbose:
        print(f"[{mailbox}] TTL local pass: candidates={candidates} matched={matched} copied={copied}")

    return candidates, matched, copied


def ignore_age_sweep(conn: sqlite3.Connection, imap: imaplib.IMAP4,
                     account: str, mailbox: str,
                     uidvalidity: int,
                     rules: List[Rule],
                     dest_mailbox: str,
                     dry_run: bool,
                     verbose: bool,
                     max_per_rule: int) -> Tuple[int, int, int]:
    uids = uid_search_all(imap)
    if verbose:
        print(f"[{mailbox}] sweep: {len(uids)} total messages (UID SEARCH ALL)")

    candidates = 0
    matched = 0
    copied = 0
    per_rule_counts: Dict[str, int] = {r.name: 0 for r in rules}

    for part in chunks(uids, 200):
        hdrs = uid_fetch_headers(imap, part)

        for uid in part:
            h = hdrs.get(uid)
            if not h:
                continue

            candidates += 1
            frm = h.get("from_raw", "") or ""
            subj = h.get("subject", "") or ""

            winner: Optional[Rule] = None
            for r in rules:
                if rule_matches(r, frm, subj):
                    winner = r
                    break

            if not winner:
                continue

            matched += 1

            if max_per_rule and per_rule_counts[winner.name] >= max_per_rule:
                continue

            if db_is_queued(conn, account, mailbox, uidvalidity, int(uid), dest_mailbox, winner.name):
                continue

            line = f'[{mailbox}] [{winner.name}] UID={uid} From="{frm}" Subject="{subj}" -> {dest_mailbox} (COPY)'

            if dry_run:
                if verbose:
                    print("DRY-RUN:", line)
                action_taken = "dry_run"
            else:
                uid_copy(imap, int(uid), dest_mailbox)
                if delete_from_source:
                    uid_mark_deleted(imap, int(uid))
                    action_taken = "copied_deleted"
                else:
                    action_taken = "copied"
                copied += 1
                if verbose:
                    print("OK:", line)
                # Only mark queued if we actually copied
                db_mark_queued(conn, account, mailbox, uidvalidity, int(uid), dest_mailbox, winner.name)

            # Keep cache useful even for sweeps (headers-only)
            db_upsert_cache(conn, account, mailbox, uidvalidity, int(uid), h)

            # Always log
            db_log_action(conn, {
                "ts": utc_now().isoformat(),
                "account": account,
                "mailbox": mailbox,
                "uidvalidity": uidvalidity,
                "uid": int(uid),
                "message_id": h.get("message_id"),
                "internaldate": h.get("internaldate"),
                "date_hdr": h.get("date_hdr"),
                "from_raw": frm,
                "subject": subj,
                "list_id": h.get("list_id"),
                "list_unsubscribe": h.get("list_unsubscribe"),
                "rule_name": winner.name,
                "action": action_taken,
                "dest_mailbox": dest_mailbox,
            })
            per_rule_counts[winner.name] += 1

    if verbose:
        print(f"[{mailbox}] sweep pass: candidates={candidates} matched={matched} copied={copied}")

    return candidates, matched, copied


# -----------------------------
# Main
# -----------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--max-per-rule", type=int, default=0)
    ap.add_argument("--ignore-age", action="store_true")
    ap.add_argument("--scan-window-days", type=int, default=None)
    ap.add_argument("--mailbox", action="append", default=[])
    args = ap.parse_args()

    cfg = load_yaml_config(expand_path(args.config))

    acct = cfg.get("account", {}) or {}
    smtp_cfg = cfg.get("smtp", {}) or {}
    db_cfg = cfg.get("database", {}) or {}
    notify = cfg.get("notify", {}) or {}
    raw_rules = cfg.get("rules", []) or []

    # Expand config paths
    if isinstance(acct.get("credentials_json"), str):
        acct["credentials_json"] = expand_path(acct["credentials_json"])
    if isinstance(smtp_cfg.get("credentials_json"), str):
        smtp_cfg["credentials_json"] = expand_path(smtp_cfg["credentials_json"])
    if isinstance(db_cfg.get("path"), str):
        db_cfg["path"] = expand_path(db_cfg["path"])

    try:
        rules = compile_rules(raw_rules)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    if not rules:
        print("No rules found in config.", file=sys.stderr)
        return 2

    db_path = db_cfg.get("path")
    if not db_path:
        print("database.path is required.", file=sys.stderr)
        return 2

    db_path = expand_path(db_path)
    db_init(db_path)

    conn = sqlite3.connect(db_path, timeout=30)
    try:
        # Credentials
        creds_path = acct.get("credentials_json")
        username = acct.get("username", "")
        creds_key = acct.get("credentials_key", username)
        delete_from_source = acct.get("delete_from_source")
        expunge_after_run = acct.get("expunge_after_run")
        
        if not creds_path or not username or not creds_key:
            print("Config must include account.username, account.credentials_json, account.credentials_key.", file=sys.stderr)
            return 2

        creds = load_creds(creds_path)
        imap_password = get_password(creds, creds_key, "password")
        if not imap_password:
            print(f"No IMAP password found in {creds_path} for key '{creds_key}'", file=sys.stderr)
            return 2

        host = acct.get("host", "")
        port = int(acct.get("port", 993))
        starttls = bool(acct.get("starttls", False))
        if not host:
            print("account.host is required.", file=sys.stderr)
            return 2

        mailbox_default = acct.get("mailbox", "INBOX")

        action = acct.get("action", "copy_to_folder")
        target_mailbox = acct.get("target_mailbox", "PurgeQueue")
        trash_mailbox = acct.get("trash_mailbox", "Trash")
        if action not in ("copy_to_folder", "copy_to_trash"):
            print("For safety, account.action must be copy_to_folder or copy_to_trash.", file=sys.stderr)
            return 2
        dest_mailbox = target_mailbox if action == "copy_to_folder" else trash_mailbox

        scan_window_days = args.scan_window_days
        if scan_window_days is None:
            scan_window_days = int(acct.get("scan_window_days", 180))

        mailboxes = args.mailbox[:] if args.mailbox else [mailbox_default]

        imap = connect_imap(host, port, starttls)
        try:
            login_imap(imap, username, imap_password)

            if args.verbose:
                typ, caps = imap.capability()
                print("IMAP capabilities:", caps)

            #ensure_mailbox_exists(imap, dest_mailbox)
            # Verify destination mailbox exists and is selectable; do NOT create it.
            typ, _ = imap.select(dest_mailbox, readonly=True)
            if typ != "OK":
                raise SystemExit(
                    f"FATAL: destination mailbox '{dest_mailbox}' does not exist or is not selectable. Aborting."
                )

            total_candidates = 0
            total_matched = 0
            total_copied = 0
            total_ingested = 0

            for mailbox in mailboxes:
                select_mailbox(imap, mailbox)
                uidvalidity, uidnext = status_uidvalidity_uidnext(imap, mailbox)

                if args.verbose:
                    print(f"\n=== Mailbox: {mailbox} (UIDVALIDITY={uidvalidity}, UIDNEXT={uidnext}) ===")

                if args.ignore_age:
                    c, m, cp = ignore_age_sweep(
                        conn=conn,
                        imap=imap,
                        account=username,
                        mailbox=mailbox,
                        uidvalidity=uidvalidity,
                        rules=rules,
                        dest_mailbox=dest_mailbox,
                        dry_run=args.dry_run,
                        verbose=args.verbose,
                        max_per_rule=args.max_per_rule,
                    )
                else:
                    ing = ingest_new_headers_ttl(
                        conn=conn,
                        imap=imap,
                        account=username,
                        mailbox=mailbox,
                        uidvalidity=uidvalidity,
                        uidnext=uidnext,
                        verbose=args.verbose,
                    )
                    total_ingested += ing

                    c, m, cp = ttl_process_from_cache(
                        conn=conn,
                        imap=imap,
                        account=username,
                        mailbox=mailbox,
                        uidvalidity=uidvalidity,
                        rules=rules,
                        dest_mailbox=dest_mailbox,
                        dry_run=args.dry_run,
                        verbose=args.verbose,
                        max_per_rule=args.max_per_rule,
                        delete_from_source=delete_from_source
                    )
                    # ... after ttl_process_from_cache / ignore_age_sweep, before moving to next mailbox
                    if (not args.dry_run) and delete_from_source and expunge_after_run:
                        typ, data = imap.expunge()
                        if typ != "OK":
                            raise RuntimeError(f"EXPUNGE failed: {data}")
                        if args.verbose:
                            print(f"[{mailbox}] EXPUNGE complete")
                    
                conn.commit()
                total_candidates += c
                total_matched += m
                total_copied += cp

            # Dead-man staleness: DISABLE when --ignore-age
            warnings: List[str] = []
            if not args.ignore_age:
                warnings = stale_rule_warnings_deadman(conn, raw_rules, utc_now(), username, mailboxes)

            summary = (
                f"mail-prune run: {utc_now().isoformat()}\n"
                f"account={username}\n"
                f"mode={'DRY-RUN' if args.dry_run else 'LIVE'}\n"
                f"mailboxes={', '.join(mailboxes)}\n"
                f"dest_mailbox={dest_mailbox}\n"
                f"ignore_age={args.ignore_age}\n"
                f"scan_window_days={scan_window_days if not args.ignore_age else 'N/A'}\n"
                f"ingested_new_headers={total_ingested if not args.ignore_age else 'N/A'}\n"
                f"candidates_considered={total_candidates}\n"
                f"matched={total_matched}\n"
                f"copied={total_copied}\n"
            )
            stale_section = "Stale-source check:\n" + ("\n".join(warnings) if warnings else "OK") + "\n"

            # Notify (skip on dry-run)
            if notify.get("enabled", False) and not args.dry_run:
                only_on_warnings = bool(notify.get("only_on_warnings", True))
                if warnings or not only_on_warnings:
                    smtp_host = smtp_cfg.get("host")
                    if not smtp_host:
                        raise RuntimeError("notify.enabled is true but smtp.host is missing.")
                    smtp_port = int(smtp_cfg.get("port", 587))
                    smtp_starttls = bool(smtp_cfg.get("starttls", True))
                    smtp_user = smtp_cfg.get("username", username)

                    smtp_creds_path = smtp_cfg.get("credentials_json", creds_path)
                    smtp_creds_key = smtp_cfg.get("credentials_key", smtp_user)
                    smtp_pw_field = smtp_cfg.get("password_field", "smtp_password")

                    smtp_creds = creds if expand_path(smtp_creds_path) == expand_path(creds_path) else load_creds(smtp_creds_path)
                    smtp_password = get_password(smtp_creds, smtp_creds_key, smtp_pw_field)
                    if not smtp_password:
                        raise RuntimeError(f"No SMTP password found for key '{smtp_creds_key}' field '{smtp_pw_field}'")

                    subject_prefix = notify.get("subject_prefix", "[mail-prune]")
                    subject = f"{subject_prefix} {'WARN' if warnings else 'OK'}"
                    body = summary + "\n" + stale_section

                    send_smtp_email(
                        host=smtp_host,
                        port=smtp_port,
                        starttls=smtp_starttls,
                        username=smtp_user,
                        password=smtp_password,
                        to_addr=notify["to"],
                        from_addr=notify["from"],
                        subject=subject,
                        body=body,
                    )
#            if not args.dry_run and delete_from_source and expunge_after_run:
#                imap.expunge()
            print(summary + "\n" + stale_section)
            return 0

        finally:
            try:
                imap.logout()
            except Exception:
                pass

    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())

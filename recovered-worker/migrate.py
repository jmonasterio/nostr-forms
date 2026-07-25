#!/usr/bin/env python3
"""
Migrate argw's forms.db (SQLite) → Cloudflare D1.

Usage:
    # 1. Pull the snapshot:
    scp jm@argw.com:/var/lib/nostr-form-rs/forms.db ./backups/

    # 2. Emit SQL files this script writes:
    python3 migrate.py ./backups/forms.db --out ./migration/

    # 3. Apply to D1:
    wrangler d1 execute nostr-form-rs --remote --file=migration/forms.sql
    wrangler d1 execute nostr-form-rs --remote --file=migration/submissions.sql
    wrangler d1 execute nostr-form-rs --remote --file=migration/rate_limits.sql

The schema this script emits matches `src/schema.rs::DDL_STATEMENTS`. If
you change the schema, change both.
"""
import argparse
import os
import sqlite3
import sys
import json
import time


def sql_escape(value):
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    return "'" + s.replace("'", "''") + "'"


def export_table(conn, dest_table, columns, source_table, source_columns, defaults=None,
                 batch_size=500, out_path=None):
    """Read rows from source_table.source_columns and emit
    INSERT OR IGNORE INTO dest_table(columns) VALUES (...);
    """
    defaults = defaults or {}
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT {','.join(source_columns)} FROM {source_table}")
    except sqlite3.OperationalError as e:
        print(f"  skip {source_table}: {e}", file=sys.stderr)
        return 0
    rows = cur.fetchall()
    if not rows:
        print(f"  {source_table}: 0 rows")
        if out_path:
            open(out_path, "w").write(f"-- {source_table}: empty\n")
        return 0

    lines = [
        f"-- migrated from {source_table} ({len(rows)} rows) at "
        f"{time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    for batch_start in range(0, len(rows), batch_size):
        batch = rows[batch_start:batch_start + batch_size]
        values = []
        for row in batch:
            row_dict = dict(zip(source_columns, row))
            row_dict.update(defaults)
            values.append("(" + ",".join(sql_escape(row_dict[c]) for c in columns) + ")")
        lines.append(
            f"INSERT OR IGNORE INTO {dest_table}({','.join(columns)}) VALUES\n"
            + ",\n".join(values) + ";"
        )
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    print(f"  {source_table}: {len(rows)} rows → {out_path}")
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("forms_db", help="path to argw's forms.db SQLite file")
    ap.add_argument("--out", default="./migration", help="output directory for .sql files")
    args = ap.parse_args()

    if not os.path.isfile(args.forms_db):
        print(f"error: {args.forms_db} not found", file=sys.stderr)
        sys.exit(1)
    os.makedirs(args.out, exist_ok=True)

    print(f"reading {args.forms_db}")
    conn = sqlite3.connect(args.forms_db)
    conn.row_factory = sqlite3.Row

    # Inspect source schema once for the operator's reference.
    cur = conn.cursor()
    print("source tables:")
    for (name,) in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name").fetchall():
        cnt = cur.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        print(f"  {name}: {cnt} rows")

    # NOTE: column names below assume the argw schema. Adjust source_columns
    # if the live forms.db schema differs — inspect with `sqlite3 forms.db .schema`.
    total = 0
    total += export_table(
        conn,
        dest_table="forms",
        columns=["slug", "admin_pubkey", "options_json", "created_at"],
        source_table="forms",
        source_columns=["slug", "admin_pubkey", "options_json", "created_at"],
        out_path=os.path.join(args.out, "forms.sql"),
    )
    total += export_table(
        conn,
        dest_table="submissions",
        columns=["event_id", "form_slug", "submitter_pubkey", "plaintext_json",
                 "created_at", "received_at", "admin_notified"],
        source_table="submissions",
        source_columns=["event_id", "form_slug", "submitter_pubkey", "plaintext_json",
                        "created_at", "received_at", "admin_notified"],
        out_path=os.path.join(args.out, "submissions.sql"),
    )
    total += export_table(
        conn,
        dest_table="rate_limits",
        columns=["submitter_pubkey", "window_start", "count"],
        source_table="rate_limits",
        source_columns=["submitter_pubkey", "window_start", "count"],
        out_path=os.path.join(args.out, "rate_limits.sql"),
    )

    print(f"\ndone — {total} rows total")
    print(f"apply with: wrangler d1 execute nostr-form-rs --remote --file={args.out}/forms.sql")


if __name__ == "__main__":
    main()

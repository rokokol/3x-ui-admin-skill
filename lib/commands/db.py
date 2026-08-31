"""Fetch the panel database, stripped of what it should not be carrying around.

A panel export is not a neutral artefact. It holds every client UUID and
password, the Reality and WireGuard private keys, subscription ids, the tokens
the master uses against its nodes, the addresses clients connected from, and a
label column that in a private fleet holds real people's names. Anyone with the
file has the fleet.

Most reasons to want a copy — reading the routing, diffing a configuration,
counting traffic — need none of that. So the copy is sanitised by default and
the whole thing is an explicit request.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

help = "fetch the panel database"

# column -> tables it appears in. Emptied rather than dropped, so the schema and
# the row counts stay true and a diff still lines up.
SECRET_COLUMNS = {
    "clients": (
        "uuid",
        "password",
        "auth",
        "secret",
        "sub_id",
        "private_key",
        "public_key",
        "pre_shared_key",
    ),
    "api_tokens": ("token",),
    "nodes": ("api_token", "pinned_cert_sha256"),
    "client_external_links": ("url",),
}

# Whole tables whose contents are personal data rather than configuration.
PERSONAL_TABLES = ("inbound_client_ips", "node_client_ips", "client_hwids")

# Settings rows that are credentials in their own right.
SECRET_SETTINGS = (
    "secret",
    "tgBotToken",
    "twoFactorToken",
    "ldapPassword",
    "smtpPassword",
    "nodeMtlsCaKeyPem",
    "nodeMtlsClientKeyPem",
    "warpSecret",
    "nordSecret",
)

# Keys to blank wherever they appear inside a JSON blob: inbound settings carry
# Reality and WireGuard keys, and the Xray template carries outbound credentials.
SECRET_JSON_KEYS = {
    "id",
    "password",
    "privatekey",
    "publickey",
    "presharedkey",
    "secretkey",
    "shortids",
    "subid",
    "auth",
    "email",
    "secret",
}


def register(parser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    pull = sub.add_parser("pull", help="download the database")
    pull.add_argument(
        "path",
        nargs="?",
        help="where to write it (default: x-ui-<panel>-<timestamp>.db here)",
    )
    pull.add_argument(
        "--with-secrets",
        action="store_true",
        help="keep credentials and personal data; writes a live copy of the fleet",
    )


def _scrub_json(value: str) -> str:
    """Blank credential-shaped keys inside a JSON document, keeping its shape."""
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value

    def walk(node):
        if isinstance(node, dict):
            return {
                key: ("" if key.lower() in SECRET_JSON_KEYS and isinstance(v, (str, int)) else walk(v))
                for key, v in node.items()
            }
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return json.dumps(walk(parsed))


def _columns(connection, table: str) -> set[str]:
    try:
        return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    except sqlite3.DatabaseError:
        return set()


def _table_exists(connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def sanitise(path: Path) -> list[str]:
    """Empty every credential in place. Returns a description of what was done."""
    done = []
    connection = sqlite3.connect(path)
    try:
        # The export arrives in WAL mode, where writes land in a side file that
        # only a checkpoint folds back in. Moving the .db alone would then move
        # the original rows and leave every edit behind, reported as success.
        connection.execute("PRAGMA journal_mode = DELETE")
        for table, columns in SECRET_COLUMNS.items():
            if not _table_exists(connection, table):
                continue
            present = _columns(connection, table) & set(columns)
            for column in sorted(present):
                connection.execute(f"UPDATE {table} SET {column} = ''")
            if present:
                done.append(f"{table}: blanked {', '.join(sorted(present))}")

        # Labels are masked rather than blanked, so rows stay distinguishable.
        if _table_exists(connection, "clients") and "email" in _columns(connection, "clients"):
            connection.execute(
                "UPDATE clients SET email = substr(email, 1, 2) || '***' || id"
            )
            done.append("clients: masked email")

        for table in PERSONAL_TABLES:
            if _table_exists(connection, table):
                count = connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                connection.execute(f"DELETE FROM {table}")
                done.append(f"{table}: removed {count} row(s)")

        if _table_exists(connection, "settings"):
            placeholders = ",".join("?" for _ in SECRET_SETTINGS)
            connection.execute(
                f"UPDATE settings SET value = '' WHERE key IN ({placeholders})",
                SECRET_SETTINGS,
            )
            done.append("settings: blanked credential keys")

            # The Xray template stays readable - it is the routing - but the
            # credentials inside it do not.
            for key, value in connection.execute(
                "SELECT key, value FROM settings WHERE key LIKE 'xrayTemplateConfig%'"
            ).fetchall():
                connection.execute(
                    "UPDATE settings SET value = ? WHERE key = ?", (_scrub_json(value), key)
                )
            done.append("settings: scrubbed credentials inside the Xray template")

        for table in ("inbounds",):
            if not _table_exists(connection, table):
                continue
            present = _columns(connection, table) & {"settings", "stream_settings"}
            for column in sorted(present):
                rows = connection.execute(
                    f"SELECT id, {column} FROM {table}"
                ).fetchall()
                for row_id, value in rows:
                    connection.execute(
                        f"UPDATE {table} SET {column} = ? WHERE id = ?",
                        (_scrub_json(value or ""), row_id),
                    )
            if present:
                done.append(f"{table}: scrubbed credentials inside {', '.join(sorted(present))}")

        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    return done


def _json_secrets(value: str) -> list[str]:
    """Credential-shaped keys still holding a value inside a JSON blob."""
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    found: list[str] = []

    def walk(node, path=""):
        if isinstance(node, dict):
            for key, item in node.items():
                here = f"{path}.{key}" if path else key
                if key.lower() in SECRET_JSON_KEYS and isinstance(item, str) and item:
                    found.append(here)
                else:
                    walk(item, here)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]")

    walk(parsed)
    return found


def verify_sanitised(path: Path) -> list[str]:
    """Look for anything the scrub was supposed to remove.

    Reporting a sanitised copy without checking would be the worst possible
    failure here: the file gets treated as safe to pass around precisely because
    the tool said so.
    """
    problems: list[str] = []
    connection = sqlite3.connect(path)
    try:
        for table, columns in SECRET_COLUMNS.items():
            if not _table_exists(connection, table):
                continue
            for column in _columns(connection, table) & set(columns):
                left = connection.execute(
                    f"SELECT count(*) FROM {table} WHERE {column} IS NOT NULL AND {column} != ''"
                ).fetchone()[0]
                if left:
                    problems.append(f"{table}.{column} still holds {left} value(s)")

        for table in PERSONAL_TABLES:
            if _table_exists(connection, table):
                left = connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                if left:
                    problems.append(f"{table} still holds {left} row(s)")

        if _table_exists(connection, "settings"):
            placeholders = ",".join("?" for _ in SECRET_SETTINGS)
            left = connection.execute(
                f"SELECT key FROM settings WHERE key IN ({placeholders}) AND value != ''",
                SECRET_SETTINGS,
            ).fetchall()
            for (key,) in left:
                problems.append(f"settings.{key} still has a value")
            for key, value in connection.execute(
                "SELECT key, value FROM settings WHERE value LIKE '{%' OR value LIKE '[%'"
            ).fetchall():
                for leak in _json_secrets(value or ""):
                    problems.append(f"settings.{key} still carries {leak}")

        if _table_exists(connection, "inbounds"):
            for column in _columns(connection, "inbounds") & {"settings", "stream_settings"}:
                for row_id, value in connection.execute(
                    f"SELECT id, {column} FROM inbounds"
                ).fetchall():
                    for leak in _json_secrets(value or ""):
                        problems.append(f"inbounds[{row_id}].{column} still carries {leak}")
    finally:
        connection.close()
    return problems


def run(args, client) -> int:
    if args.command != "pull":
        print(f"unknown command: {args.command}")
        return 2

    raw = client.download("server/getDb")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = Path(args.path) if args.path else Path(f"x-ui-{client.config.name}-{stamp}.db")

    handle, temporary = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    temporary_path = Path(temporary)
    temporary_path.write_bytes(raw)

    try:
        # Closed explicitly: sqlite3's context manager commits a transaction, it
        # does not close the connection, and a connection left open blocks the
        # checkpoint that the sanitising pass depends on.
        probe = sqlite3.connect(temporary_path)
        try:
            probe.execute("SELECT count(*) FROM sqlite_master").fetchone()
        finally:
            probe.close()
    except sqlite3.DatabaseError as error:
        temporary_path.unlink(missing_ok=True)
        print(f"the panel returned {len(raw)} bytes that are not a database: {error}")
        return 1

    if args.with_secrets:
        temporary_path.replace(destination)
        destination.chmod(0o600)
        print(f"wrote {destination} ({destination.stat().st_size} bytes), mode 600")
        print("This is a live copy of the fleet: every client credential, the")
        print("Reality and WireGuard keys and the node tokens are in it.")
        return 0

    actions = sanitise(temporary_path)
    problems = verify_sanitised(temporary_path)
    if problems:
        temporary_path.unlink(missing_ok=True)
        print("REFUSED: the copy still contains secrets after scrubbing, so nothing")
        print("was written. Report this - the panel schema has moved:")
        for problem in problems[:20]:
            print(f"  {problem}")
        return 1

    temporary_path.replace(destination)
    destination.chmod(0o600)
    print(f"wrote {destination} ({destination.stat().st_size} bytes), sanitised:")
    for action in actions:
        print(f"  {action}")
    print("verified: no credential-shaped value survived the scrub")
    print("\nPass --with-secrets for a restorable copy.")
    return 0

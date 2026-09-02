"""Fetch the panel database, stripped of what it should not be carrying around.

A panel export is not a neutral artefact. It holds every client UUID and
password, the Reality and WireGuard private keys, subscription ids, the tokens
the master uses against its nodes, the panel administrator's password hash, the
addresses clients connected from, and a label column that in a private fleet
holds real people's names. Anyone with the file has the fleet.

Most reasons to want a copy — reading the routing, diffing a configuration,
counting traffic — need none of that. So the copy is sanitised by default and
the whole thing is an explicit request.

The scrub is checked by a pass that does not trust the scrub's own lists: every
credential read out of the original is searched for in the bytes of the copy,
and any cell anywhere that still has the shape of a key is reported. The lists
below were written against one schema and the panel's schema moves; a check
that shares them would confirm their blind spots.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from ..secret_keys import holds_secret, is_personal, is_secret

help = "fetch the panel database"

# column -> tables it appears in. Emptied rather than dropped, so the schema and
# the row counts stay true and a diff still lines up. Names from more than one
# panel version are listed; a column that does not exist is skipped.
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
        "wg_private_key",
        "wg_public_key",
        "wg_pre_shared_key",
    ),
    "api_tokens": ("token",),
    # base_path is the node's secret URL prefix, exactly as the panel's own is.
    "nodes": ("api_token", "pinned_cert_sha256", "base_path"),
    # A subscription link is a bearer credential; the column has been called
    # both of these.
    "client_external_links": ("url", "value"),
    "outbound_subscriptions": ("url",),
    # The panel administrator. Hashed, but a hash of a password is still the
    # thing an offline attacker wants.
    "users": ("password",),
}

# Whole tables whose contents are personal data rather than configuration.
PERSONAL_TABLES = ("inbound_client_ips", "node_client_ips", "client_hwids")

# Client labels appear in more tables than the clients table. They are masked
# to the same stub everywhere, so a diff still joins across tables.
LABEL_COLUMNS = {
    "clients": "email",
    "client_traffics": "email",
    "client_global_traffics": "email",
    "node_client_traffics": "email",
}

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

# Columns whose values legitimately look like keys and are not: identifiers
# that join rows across tables, public material, and the migration log, whose
# entries are Go identifiers long enough to pass for a key.
SHAPE_ALLOWLIST_PARTS = ("guid", "ech_config_list", "hwid_hash")
SHAPE_ALLOWLIST_TABLES = ("history_of_seeders",)
SETTINGS_SHAPE_ALLOWLIST = ("panelGuid",)

# The shape of a credential as this panel stores them: base64 or hex of some
# length, or a UUID. A path, a hostname or a sentence never matches.
_CREDENTIAL_SHAPE = re.compile(r"^(?:[A-Za-z0-9+/_=-]{24,}|[0-9a-fA-F-]{32,36})$")


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
    pull.add_argument("--force", action="store_true", help="overwrite an existing file")


def _scrub_json(value: str) -> str:
    """Blank credential-shaped keys inside a JSON document, keeping its shape."""
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, item in node.items():
                if (is_secret(key) or is_personal(key)) and holds_secret(item):
                    out[key] = [] if isinstance(item, list) else ""
                else:
                    out[key] = walk(item)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return json.dumps(walk(parsed))


def _json_secrets(value: str) -> list[tuple[str, list[str]]]:
    """(path, values) for every credential-shaped key still holding a value."""
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    found: list[tuple[str, list[str]]] = []

    def walk(node, path=""):
        if isinstance(node, dict):
            for key, item in node.items():
                here = f"{path}.{key}" if path else key
                if (is_secret(key) or is_personal(key)) and holds_secret(item):
                    found.append((here, item if isinstance(item, list) else [item]))
                else:
                    walk(item, here)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]")

    walk(parsed)
    return found


def _columns(connection, table: str) -> list[str]:
    try:
        return [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
    except sqlite3.DatabaseError:
        return []


def _tables(connection) -> list[str]:
    return [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]


def _table_exists(connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _is_json(value) -> bool:
    return isinstance(value, str) and value.lstrip().startswith(("{", "["))


def _label_stub(email: str, row_id) -> str:
    return f"{email[:2]}***{row_id}"


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
            present = set(_columns(connection, table)) & set(columns)
            for column in sorted(present):
                connection.execute(f"UPDATE {table} SET {column} = ''")
            if present:
                done.append(f"{table}: blanked {', '.join(sorted(present))}")

        # Labels are masked rather than blanked, so rows stay distinguishable,
        # and to the same stub in every table so they still join.
        stubs: dict[str, str] = {}
        if _table_exists(connection, "clients") and "email" in _columns(connection, "clients"):
            for row_id, email in connection.execute("SELECT id, email FROM clients").fetchall():
                if email:
                    stubs[email] = _label_stub(email, row_id)
        for table, column in LABEL_COLUMNS.items():
            if not _table_exists(connection, table) or column not in _columns(connection, table):
                continue
            for (email,) in connection.execute(
                f"SELECT DISTINCT {column} FROM {table} WHERE {column} != ''"
            ).fetchall():
                stub = stubs.get(email) or _label_stub(email, "")
                connection.execute(
                    f"UPDATE {table} SET {column} = ? WHERE {column} = ?", (stub, email)
                )
            done.append(f"{table}: masked {column}")

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
            # credentials inside it do not. Any other JSON-valued setting is
            # treated the same way.
            for key, value in connection.execute("SELECT key, value FROM settings").fetchall():
                if _is_json(value):
                    connection.execute(
                        "UPDATE settings SET value = ? WHERE key = ?", (_scrub_json(value), key)
                    )
            done.append("settings: scrubbed credentials inside JSON values")

        for table in _tables(connection):
            if table == "settings":
                continue
            columns = _columns(connection, table)
            if "id" not in columns:
                continue
            scrubbed = []
            for column in columns:
                rows = connection.execute(f"SELECT id, {column} FROM {table}").fetchall()
                touched = False
                for row_id, value in rows:
                    if _is_json(value):
                        connection.execute(
                            f"UPDATE {table} SET {column} = ? WHERE id = ?",
                            (_scrub_json(value), row_id),
                        )
                        touched = True
                if touched:
                    scrubbed.append(column)
            if scrubbed:
                done.append(f"{table}: scrubbed credentials inside {', '.join(scrubbed)}")

        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    return done


def collect_credentials(path: Path) -> set[str]:
    """Every credential value the original holds, by the same lists the scrub uses.

    Read before the scrub, searched for after it: a value that the scrub was
    supposed to remove and did not is found by content, whichever cell it hid
    in. Short values are skipped, since a two-letter password matches anything.
    """
    found: set[str] = set()

    def add(value):
        if isinstance(value, str) and len(value) >= 6:
            found.add(value)
        elif isinstance(value, list):
            for item in value:
                add(item)

    connection = sqlite3.connect(path)
    try:
        for table, columns in SECRET_COLUMNS.items():
            if not _table_exists(connection, table):
                continue
            for column in set(_columns(connection, table)) & set(columns):
                for (value,) in connection.execute(f"SELECT {column} FROM {table}"):
                    add(value)
        if _table_exists(connection, "settings"):
            placeholders = ",".join("?" for _ in SECRET_SETTINGS)
            for (value,) in connection.execute(
                f"SELECT value FROM settings WHERE key IN ({placeholders})", SECRET_SETTINGS
            ):
                add(value)
        for table in _tables(connection):
            for column in _columns(connection, table):
                for (value,) in connection.execute(f"SELECT {column} FROM {table}"):
                    if _is_json(value):
                        for _, values in _json_secrets(value):
                            add(values)
    finally:
        connection.close()
    return found


def verify_sanitised(path: Path, credentials: Iterable[str] = ()) -> list[str]:
    """Look for anything the scrub was supposed to remove.

    Reporting a sanitised copy without checking would be the worst possible
    failure here: the file gets treated as safe to pass around precisely because
    the tool said so. Three passes, each blind to a different mistake: the
    lists (a column that was not emptied), the bytes (a credential that moved
    somewhere the lists do not know), and the shape (a key in a column nobody
    listed at all).
    """
    problems: list[str] = []
    connection = sqlite3.connect(path)
    try:
        for table, columns in SECRET_COLUMNS.items():
            if not _table_exists(connection, table):
                continue
            for column in set(_columns(connection, table)) & set(columns):
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

        for table in _tables(connection):
            if table in SHAPE_ALLOWLIST_TABLES:
                continue
            columns = _columns(connection, table)
            key_column = "key" if table == "settings" and "key" in columns else None
            for column in columns:
                select = f"SELECT {key_column or 'rowid'}, {column} FROM {table}"
                for row_key, value in connection.execute(select).fetchall():
                    where = f"{table}.{row_key}" if key_column else f"{table}[{row_key}].{column}"
                    if _is_json(value):
                        for leak, _ in _json_secrets(value):
                            problems.append(f"{where} still carries {leak}")
                        continue
                    if not isinstance(value, str) or not _CREDENTIAL_SHAPE.match(value):
                        continue
                    if any(part in column.lower() for part in SHAPE_ALLOWLIST_PARTS):
                        continue
                    if key_column and row_key in SETTINGS_SHAPE_ALLOWLIST:
                        continue
                    problems.append(f"{where} looks like a credential ({len(value)} chars)")
    finally:
        connection.close()

    blob = Path(path).read_bytes()
    leaked = sorted(v for v in credentials if v.encode() in blob)
    if leaked:
        problems.append(
            f"{len(leaked)} credential value(s) read from the original are still in "
            "the bytes of the copy"
        )
    return problems


def run(args, client) -> int:
    if args.command != "pull":
        print(f"unknown command: {args.command}")
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = Path(args.path) if args.path else Path(f"x-ui-{client.config.name}-{stamp}.db")
    if destination.exists() and not args.force:
        print(f"{destination} exists; pass --force to overwrite it")
        return 2

    raw = client.download("server/getDb")

    # The scratch file lives beside the destination: a rename across file
    # systems fails, and /tmp is one of its own on most machines. Whatever
    # happens, the scratch copy does not outlive this call.
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".part"
    )
    os.close(handle)
    temporary_path = Path(temporary)
    try:
        temporary_path.write_bytes(raw)

        try:
            # Closed explicitly: sqlite3's context manager commits a
            # transaction, it does not close the connection, and a connection
            # left open blocks the checkpoint that the sanitising pass depends on.
            probe = sqlite3.connect(temporary_path)
            try:
                probe.execute("SELECT count(*) FROM sqlite_master").fetchone()
            finally:
                probe.close()
        except sqlite3.DatabaseError as error:
            print(f"the panel returned {len(raw)} bytes that are not a database: {error}")
            return 1

        if args.with_secrets:
            temporary_path.chmod(0o600)
            temporary_path.replace(destination)
            print(f"wrote {destination} ({destination.stat().st_size} bytes), mode 600")
            print("This is a live copy of the fleet: every client credential, the")
            print("Reality and WireGuard keys and the node tokens are in it.")
            return 0

        credentials = collect_credentials(temporary_path)
        actions = sanitise(temporary_path)
        problems = verify_sanitised(temporary_path, credentials)
        if problems:
            print("REFUSED: the copy still contains secrets after scrubbing, so nothing")
            print("was written. Report this - the panel schema has moved:")
            for problem in problems[:20]:
                print(f"  {problem}")
            if len(problems) > 20:
                print(f"  … and {len(problems) - 20} more")
            return 1

        temporary_path.chmod(0o600)
        temporary_path.replace(destination)
    finally:
        temporary_path.unlink(missing_ok=True)

    print(f"wrote {destination} ({destination.stat().st_size} bytes), sanitised:")
    for action in actions:
        print(f"  {action}")
    print(f"verified: none of {len(credentials)} credential value(s) survived, nothing key-shaped left")
    print("\nPass --with-secrets for a restorable copy.")
    return 0

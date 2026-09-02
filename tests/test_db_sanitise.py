"""Scrubbing a database export, and proving the scrub happened.

The dangerous failure here is not leaving a secret in — it is reporting a clean
copy that is not clean, because that is exactly when the file gets passed
around. So the scrub is checked by a separate pass that knows nothing about
which statements ran, and that pass is itself tested against a copy nobody
scrubbed.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.commands.db import (
    collect_credentials,
    sanitise,
    verify_sanitised,
)

REALITY_KEY = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd"
CLIENT_UUID = "11111111-2222-3333-4444-555555555555"
WG_KEY = "wGpRiVaTeKeYwGpRiVaTeKeYwGpRiVaTeKeY0123456="
ADMIN_HASH = "$2a$10$oK7adminadminadminadminadminadminadminadminadminadmin"
TLS_KEY_LINE = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"
SOCKS_PASS = "sockspassword1"
SUB_LINK = "https://sub.example/sub/abcdefabcdefabcdef"

TEMPLATE = {
    "routing": {"rules": [{"outboundTag": "direct", "domain": ["geosite:category-ru"]}]},
    "outbounds": [
        {"tag": "transit", "settings": {"vnext": [{"users": [{"id": CLIENT_UUID}]}]}},
        {"tag": "corp", "protocol": "socks", "settings": {"servers": [{"users": [{"user": "u", "pass": SOCKS_PASS}]}]}},
    ],
}

INBOUND_SETTINGS = {"clients": [{"id": CLIENT_UUID, "email": "someone", "flow": "xtls-rprx-vision"}]}
STREAM_SETTINGS = {"realitySettings": {"privateKey": REALITY_KEY, "dest": "example.com:443"}}
TLS_STREAM_SETTINGS = {
    "security": "tls",
    "tlsSettings": {
        "certificates": [
            {"certificate": ["-----BEGIN CERTIFICATE-----", "MIIC"], "key": ["-----BEGIN PRIVATE KEY-----", TLS_KEY_LINE]}
        ]
    },
}


def build(path: Path) -> None:
    connection = sqlite3.connect(path)
    # The panel's export is in WAL mode, where writes land in a side file until
    # a checkpoint folds them in. A fixture in the default journal mode cannot
    # reproduce the failure that shipped: a scrub reported as done, written to
    # the side file, and lost when only the .db was moved.
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(
        """
        CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, uuid TEXT,
                              password TEXT, auth TEXT, secret TEXT, sub_id TEXT,
                              wg_private_key TEXT, wg_public_key TEXT, wg_pre_shared_key TEXT);
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, login_epoch INTEGER);
        CREATE TABLE api_tokens (id INTEGER PRIMARY KEY, name TEXT, token TEXT);
        CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT, api_token TEXT,
                            pinned_cert_sha256 TEXT, base_path TEXT, guid TEXT);
        CREATE TABLE client_external_links (id INTEGER PRIMARY KEY, client_id INTEGER, kind TEXT, value TEXT);
        CREATE TABLE outbound_subscriptions (id INTEGER PRIMARY KEY, remark TEXT, url TEXT);
        CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INTEGER, email TEXT, up INTEGER);
        CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT);
        CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, settings TEXT,
                               stream_settings TEXT);
        CREATE TABLE inbound_client_ips (id INTEGER PRIMARY KEY, client_email TEXT, ips TEXT);
        CREATE TABLE node_client_ips (id INTEGER PRIMARY KEY, node_guid TEXT, ips TEXT);
        CREATE TABLE client_hwids (id INTEGER PRIMARY KEY, sub_id TEXT, hwid TEXT);
        """
    )
    connection.execute(
        "INSERT INTO clients (email, uuid, password, auth, secret, sub_id, wg_private_key, wg_public_key, wg_pre_shared_key)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        ("Relative", CLIENT_UUID, "hunter2", "authvalue", "secretvalue", "subidvalue", WG_KEY, "pub" + WG_KEY, "psk" + WG_KEY),
    )
    connection.execute("INSERT INTO users (username, password, login_epoch) VALUES ('admin', ?, 0)", (ADMIN_HASH,))
    connection.execute("INSERT INTO api_tokens (name, token) VALUES ('cli', 'tokenvalue')")
    connection.execute(
        "INSERT INTO nodes (name, api_token, pinned_cert_sha256, base_path, guid) VALUES "
        "('n', 'nodetoken', 'aa:bb', '/s3cr3tbasepath/', '9e9e9e9e-1111-2222-3333-444444444444')"
    )
    connection.execute("INSERT INTO client_external_links (client_id, kind, value) VALUES (1, 'sub', ?)", (SUB_LINK,))
    connection.execute("INSERT INTO outbound_subscriptions (remark, url) VALUES ('up', ?)", (SUB_LINK + "?upstream",))
    connection.execute("INSERT INTO client_traffics (inbound_id, email, up) VALUES (1, 'Relative', 5)")
    connection.execute(
        "INSERT INTO inbounds (remark, settings, stream_settings) VALUES (?,?,?)",
        ("tls-in", json.dumps({"clients": []}), json.dumps(TLS_STREAM_SETTINGS)),
    )
    connection.execute(
        "INSERT INTO settings (key, value) VALUES ('secret', 'panelsecret')"
    )
    connection.execute(
        "INSERT INTO settings (key, value) VALUES ('xrayTemplateConfig', ?)",
        (json.dumps(TEMPLATE),),
    )
    connection.execute(
        "INSERT INTO inbounds (remark, settings, stream_settings) VALUES (?,?,?)",
        ("in", json.dumps(INBOUND_SETTINGS), json.dumps(STREAM_SETTINGS)),
    )
    connection.execute(
        "INSERT INTO inbound_client_ips (client_email, ips) VALUES ('Relative', '203.0.113.1')"
    )
    connection.execute("INSERT INTO node_client_ips (node_guid, ips) VALUES ('g', '203.0.113.2')")
    connection.commit()
    connection.close()


class TestSanitise(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "x-ui.db"
        build(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def read(self, query: str):
        connection = sqlite3.connect(self.path)
        try:
            return connection.execute(query).fetchall()
        finally:
            connection.close()

    def test_unscrubbed_copy_is_caught(self):
        # The check must fail on a copy nobody cleaned, or passing it proves
        # nothing about a copy that was.
        problems = verify_sanitised(self.path)
        self.assertTrue(problems)
        joined = " ".join(problems)
        self.assertIn("clients.uuid", joined)
        self.assertIn("inbound_client_ips", joined)

    def test_scrub_leaves_nothing_the_check_can_find(self):
        credentials = collect_credentials(self.path)
        self.assertIn(ADMIN_HASH, credentials)
        self.assertIn(TLS_KEY_LINE, credentials)
        sanitise(self.path)
        self.assertEqual(verify_sanitised(self.path, credentials), [])

    def test_credentials_are_gone_from_the_bytes(self):
        sanitise(self.path)
        blob = self.path.read_bytes()
        for secret in (
            CLIENT_UUID,
            REALITY_KEY,
            "hunter2",
            "panelsecret",
            "nodetoken",
            # Each of these shipped in a "sanitised" copy once: the column was
            # named differently from the list, the key was spelled `key` or
            # `pass`, or the table was not on the list at all.
            WG_KEY,
            ADMIN_HASH,
            TLS_KEY_LINE,
            SOCKS_PASS,
            SUB_LINK,
            "s3cr3tbasepath",
        ):
            self.assertNotIn(secret.encode(), blob, f"{secret} survived the scrub")

    def test_the_check_finds_what_the_lists_miss(self):
        # A credential in a column the scrub does not know about must still be
        # reported: by content, because the original told us the value; and by
        # shape, because a key looks like a key wherever it sits.
        connection = sqlite3.connect(self.path)
        connection.execute("ALTER TABLE nodes ADD COLUMN spare TEXT")
        connection.execute("UPDATE nodes SET spare = ?", (REALITY_KEY,))
        connection.commit()
        connection.close()
        credentials = collect_credentials(self.path)
        sanitise(self.path)
        problems = verify_sanitised(self.path, credentials)
        self.assertTrue(any("nodes[1].spare looks like a credential" in p for p in problems), problems)
        self.assertTrue(any("still in the bytes" in p for p in problems), problems)

    def test_identifiers_are_not_mistaken_for_credentials(self):
        # A node guid is a UUID that joins rows; it stays, and does not trip
        # the shape check.
        credentials = collect_credentials(self.path)
        sanitise(self.path)
        self.assertEqual(verify_sanitised(self.path, credentials), [])
        self.assertEqual(self.read("SELECT guid FROM nodes")[0][0], "9e9e9e9e-1111-2222-3333-444444444444")

    def test_labels_match_across_tables(self):
        # client_traffics joins on the label, so it is masked to the same stub.
        sanitise(self.path)
        self.assertEqual(
            self.read("SELECT email FROM clients")[0][0],
            self.read("SELECT email FROM client_traffics")[0][0],
        )

    def test_structure_and_routing_survive(self):
        sanitise(self.path)
        self.assertEqual(self.read("SELECT count(*) FROM clients")[0][0], 1)
        template = json.loads(
            self.read("SELECT value FROM settings WHERE key='xrayTemplateConfig'")[0][0]
        )
        # The routing is the reason to take a copy at all.
        self.assertEqual(len(template["routing"]["rules"]), 1)
        self.assertEqual(template["routing"]["rules"][0]["outboundTag"], "direct")
        self.assertEqual(template["outbounds"][0]["tag"], "transit")

    def test_labels_stay_distinguishable(self):
        sanitise(self.path)
        email = self.read("SELECT email FROM clients")[0][0]
        self.assertNotEqual(email, "Relative")
        self.assertTrue(email.startswith("Re"))

    def test_personal_tables_are_emptied(self):
        sanitise(self.path)
        self.assertEqual(self.read("SELECT count(*) FROM inbound_client_ips")[0][0], 0)
        self.assertEqual(self.read("SELECT count(*) FROM node_client_ips")[0][0], 0)

    def test_the_copy_carries_no_side_journal(self):
        # The scrub has to leave a single self-contained file, because the caller
        # moves the .db and nothing else. Asserting the journal mode states that
        # directly, rather than hoping a checkpoint happened to run.
        sanitise(self.path)
        mode = self.read("PRAGMA journal_mode")[0][0]
        self.assertEqual(mode.lower(), "delete", "a -wal file would be left behind")
        self.assertFalse(
            (self.path.parent / (self.path.name + "-wal")).exists(),
            "the write-ahead log still exists beside the database",
        )

    def test_edits_survive_a_move(self):
        # Regression: the export arrives in WAL mode, so edits live in a side
        # file until a checkpoint. Moving the .db alone used to move the
        # original rows while the report claimed a clean scrub.
        sanitise(self.path)
        moved = self.path.parent / "moved.db"
        self.path.replace(moved)
        connection = sqlite3.connect(moved)
        try:
            left = connection.execute(
                "SELECT count(*) FROM clients WHERE uuid != ''"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(left, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

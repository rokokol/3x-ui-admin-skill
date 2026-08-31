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

from lib.commands.db import sanitise, verify_sanitised  # noqa: E402

REALITY_KEY = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd"
CLIENT_UUID = "11111111-2222-3333-4444-555555555555"

TEMPLATE = {
    "routing": {"rules": [{"outboundTag": "direct", "domain": ["geosite:category-ru"]}]},
    "outbounds": [
        {"tag": "transit", "settings": {"vnext": [{"users": [{"id": CLIENT_UUID}]}]}}
    ],
}

INBOUND_SETTINGS = {"clients": [{"id": CLIENT_UUID, "email": "someone", "flow": "xtls-rprx-vision"}]}
STREAM_SETTINGS = {"realitySettings": {"privateKey": REALITY_KEY, "dest": "example.com:443"}}


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
                              password TEXT, auth TEXT, secret TEXT, sub_id TEXT);
        CREATE TABLE api_tokens (id INTEGER PRIMARY KEY, name TEXT, token TEXT);
        CREATE TABLE nodes (id INTEGER PRIMARY KEY, name TEXT, api_token TEXT,
                            pinned_cert_sha256 TEXT);
        CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT);
        CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, settings TEXT,
                               stream_settings TEXT);
        CREATE TABLE inbound_client_ips (id INTEGER PRIMARY KEY, client_email TEXT, ips TEXT);
        CREATE TABLE node_client_ips (id INTEGER PRIMARY KEY, node_guid TEXT, ips TEXT);
        CREATE TABLE client_hwids (id INTEGER PRIMARY KEY, sub_id TEXT, hwid TEXT);
        """
    )
    connection.execute(
        "INSERT INTO clients (email, uuid, password, auth, secret, sub_id) VALUES (?,?,?,?,?,?)",
        ("Relative", CLIENT_UUID, "hunter2", "authvalue", "secretvalue", "subidvalue"),
    )
    connection.execute("INSERT INTO api_tokens (name, token) VALUES ('cli', 'tokenvalue')")
    connection.execute(
        "INSERT INTO nodes (name, api_token, pinned_cert_sha256) VALUES ('n', 'nodetoken', 'aa:bb')"
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
        sanitise(self.path)
        self.assertEqual(verify_sanitised(self.path), [])

    def test_credentials_are_gone_from_the_bytes(self):
        sanitise(self.path)
        blob = self.path.read_bytes()
        for secret in (CLIENT_UUID, REALITY_KEY, b"hunter2".decode(), "panelsecret", "nodetoken"):
            self.assertNotIn(secret.encode(), blob, f"{secret} survived the scrub")

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

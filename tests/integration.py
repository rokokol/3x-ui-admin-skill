"""End-to-end tests against a real panel in a throwaway container.

The unit tests describe how the panel behaves; these prove it. They run the same
commands against a real 3x-ui, on a database nobody minds losing, so a mutation
guard can be exercised by actually corrupting a client rather than by asking a
stub to pretend.

    python3 tests/integration.py            # pulls the image, runs, cleans up
    KEEP=1 python3 tests/integration.py     # leave the container for poking at

Needs docker and network access on the first run. Skips itself with a clear
message when docker is unavailable, so it can sit in the same suite as the
offline tests without breaking them.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import api, config
from lib.commands import client_edit
from lib.commands import db as db_cmd
from lib.snapshot import apply_and_verify

IMAGE = os.environ.get("XUI_TEST_IMAGE", "ghcr.io/mhsanaei/3x-ui:v3.7.0")
CONTAINER = os.environ.get("XUI_TEST_CONTAINER", "xui-integration")
PORT = int(os.environ.get("XUI_TEST_PORT", "25354"))


def docker(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


class Panel:
    """A disposable 3x-ui, started once for the whole module."""

    def __init__(self):
        self.client: api.Client | None = None

    def start(self) -> None:
        docker("rm", "-f", CONTAINER, check=False)
        docker("run", "-d", "--name", CONTAINER, "-p", f"{PORT}:2053", IMAGE)

        token = ""
        for _ in range(30):
            time.sleep(1)
            out = docker(
                "exec", CONTAINER, "/app/x-ui", "setting", "-getApiToken", check=False
            )
            found = re.search(r"[A-Za-z0-9]{40,}", out)
            if found:
                token = found.group(0)
                break
        if not token:
            logs = docker("logs", CONTAINER, check=False)[-800:]
            raise RuntimeError(f"panel never produced a token. Last logs:\n{logs}")

        self.client = api.Client(
            config.PanelConfig(
                url=f"http://127.0.0.1:{PORT}",
                token=token,
                verify_tls=False,
                name="integration",
            )
        )
        # The panel answers before it finishes migrating, so wait for a real read
        for _ in range(30):
            try:
                self.client.get("inbounds/list")
                return
            except api.ApiError:
                time.sleep(1)
        raise RuntimeError("panel never served its API")

    def stop(self) -> None:
        if os.environ.get("KEEP"):
            print(f"\nleaving {CONTAINER} running on port {PORT}")
            return
        docker("rm", "-f", CONTAINER, check=False)


PANEL = Panel()


def setUpModule() -> None:
    if shutil.which("docker") is None:
        raise unittest.SkipTest("docker not available")
    try:
        PANEL.start()
    except RuntimeError as error:
        raise unittest.SkipTest(f"cannot start a test panel: {error}") from error


def tearDownModule() -> None:
    PANEL.stop()


VISION_INBOUND = {
    "remark": "integration-vision",
    "protocol": "vless",
    "port": 24443,
    "listen": "",
    "enable": True,
    "settings": json.dumps({"clients": [], "decryption": "none", "fallbacks": []}),
    "streamSettings": json.dumps(
        {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": "example.com:443",
                "serverNames": ["example.com"],
                "privateKey": "OB2fLTZ5nCJbfQmBcnPGwJlm5vDkVAFsF0bZUtEEMHg",
                "shortIds": ["0123abcd"],
                "settings": {"publicKey": "x", "fingerprint": "chrome"},
            },
            "tcpSettings": {"header": {"type": "none"}},
        }
    ),
    "sniffing": json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"]}),
}


class TestAgainstRealPanel(unittest.TestCase):
    inbound_id: int
    client: api.Client

    @classmethod
    def setUpClass(cls):
        assert PANEL.client is not None
        cls.client = PANEL.client
        created = cls.client.post("inbounds/add", body=VISION_INBOUND)
        cls.inbound_id = (created or {}).get("id") or cls._find_inbound(cls.client)

    @staticmethod
    def _find_inbound(client) -> int:
        for item in client.get("inbounds/list") or []:
            if item.get("remark") == VISION_INBOUND["remark"]:
                return item["id"]
        raise RuntimeError("the inbound this suite needs was not created")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.post(f"inbounds/del/{cls.inbound_id}")
        except api.ApiError:
            pass
        try:
            cls.client.post("clients/delOrphans")
        except api.ApiError:
            pass

    def _add_client(self, email: str, flow: str = "xtls-rprx-vision") -> None:
        self.client.post(
            "clients/add",
            body={
                "client": {"email": email, "enable": True, "flow": flow},
                "inboundIds": [self.inbound_id],
            },
        )

    def _read(self, email: str) -> dict:
        return dict(self.client.get(f"clients/get/{email}")["client"])

    def _delete(self, email: str) -> None:
        try:
            self.client.post(f"clients/del/{email}")
        except api.ApiError:
            pass

    def test_add_sets_the_flow_when_asked_explicitly(self):
        email = "it-flow"
        self.addCleanup(self._delete, email)
        self._add_client(email)
        self.assertEqual(self._read(email)["flow"], "xtls-rprx-vision")

    def test_a_partial_update_really_does_destroy_the_client(self):
        # This is the whole reason the guard exists. If the panel ever stops
        # behaving this way, the guard can be reconsidered - but not before.
        email = "it-naive"
        self.addCleanup(self._delete, email)
        self._add_client(email)
        before = self._read(email)

        self.client.post(
            f"clients/update/{email}",
            body={"email": email, "id": before["uuid"], "totalGB": 1024, "allowedIPs": []},
        )

        after = self._read(email)
        self.assertEqual(after["flow"], "", "panel no longer clears flow on partial update")
        self.assertFalse(after["enable"], "panel no longer disables on partial update")

    def test_the_guarded_path_keeps_every_other_field(self):
        email = "it-guarded"
        self.addCleanup(self._delete, email)
        self._add_client(email)

        applied = apply_and_verify(
            client_edit._reader(self.client, email),
            client_edit._writer(self.client, email),
            {"totalGB": 2048},
        )

        after = self._read(email)
        self.assertEqual(set(applied.changed), {"totalGB"})
        self.assertEqual(after["flow"], "xtls-rprx-vision")
        self.assertTrue(after["enable"])
        self.assertEqual(after["totalGB"], 2048)

    def test_the_panel_accepts_a_flow_xray_never_heard_of(self):
        # Measured, not assumed: the panel validates nothing here. It stores the
        # string, serves it, and the client fails to connect while the panel
        # shows it as healthy - which is why the skill warns on an unknown flow
        # rather than trusting the panel to refuse one.
        email = "it-badflow"
        self.addCleanup(self._delete, email)
        self._add_client(email)

        applied = apply_and_verify(
            client_edit._reader(self.client, email),
            client_edit._writer(self.client, email),
            {"flow": "not-a-real-flow"},
        )
        self.assertEqual(set(applied.changed), {"flow"})
        self.assertEqual(self._read(email)["flow"], "not-a-real-flow")
        self.assertNotIn("not-a-real-flow", client_edit.KNOWN_FLOWS)

    def test_deleting_a_client_is_clean(self):
        email = "it-delete"
        self._add_client(email)
        self.client.post(f"clients/del/{email}")
        remaining = [c.get("email") for c in self.client.get("clients/list") or []]
        self.assertNotIn(email, remaining)

    def test_deleting_an_inbound_orphans_its_clients(self):
        # The asymmetry the skill reports on: a client survives its inbound.
        spare = dict(VISION_INBOUND, remark="integration-spare", port=24444)
        created = self.client.post("inbounds/add", body=spare)
        spare_id = (created or {}).get("id")
        self.assertIsNotNone(spare_id)

        email = "it-orphan"
        self.addCleanup(self._delete, email)
        self.client.post(
            "clients/add",
            body={"client": {"email": email, "enable": True}, "inboundIds": [spare_id]},
        )
        self.client.post(f"inbounds/del/{spare_id}")

        survivors = {
            c.get("email"): (c.get("inboundIds") or [])
            for c in self.client.get("clients/list") or []
        }
        self.assertIn(email, survivors)
        self.assertEqual(survivors[email], [], "client should have no attachments left")

        self.client.post("clients/delOrphans")
        after = [c.get("email") for c in self.client.get("clients/list") or []]
        self.assertNotIn(email, after)

    def test_inbound_validation_reads_a_real_inbound(self):
        from lib.inbound_checks import check_inbound

        inbound = self.client.get(f"inbounds/get/{self.inbound_id}")
        problems, _ = check_inbound(inbound)
        self.assertEqual(problems, [], f"a well-formed inbound reported: {problems}")

    def test_inbound_validation_catches_a_missing_quic_override(self):
        inbound = self.client.get(f"inbounds/get/{self.inbound_id}")
        broken = dict(inbound)
        broken["sniffing"] = json.dumps({"enabled": True, "destOverride": ["http", "tls"]})
        from lib.inbound_checks import check_inbound

        problems, _ = check_inbound(broken)
        self.assertTrue(any("quic" in p for p in problems))

    def test_a_label_with_a_question_mark_can_still_be_addressed(self):
        # The panel refuses `/` and spaces in a label but accepts `?` and `#`.
        # Unescaped in the path, such a client exists and cannot be reached.
        email = "it-q?x=1#f"
        self.addCleanup(self._delete_quoted, email)
        self._add_client(email)
        read = client_edit._reader(self.client, email)()
        self.assertEqual(read["email"], email)
        applied = apply_and_verify(
            client_edit._reader(self.client, email),
            client_edit._writer(self.client, email),
            {"totalGB": 4096},
        )
        self.assertEqual(set(applied.changed), {"totalGB"})

    def _delete_quoted(self, email: str) -> None:
        try:
            self.client.post(api.path("clients", "del", email))
        except api.ApiError:
            pass

    def test_a_negative_expiry_is_accepted_and_is_not_expired(self):
        from lib.commands.client import _expiry

        email = "it-delayed"
        self.addCleanup(self._delete, email)
        self.client.post(
            "clients/add",
            body={
                "client": {"email": email, "enable": True, "expiryTime": -864_000_000},
                "inboundIds": [self.inbound_id],
            },
        )
        stored = self._read(email)["expiryTime"]
        self.assertLess(stored, 0, "the panel no longer stores a delayed start as a negative")
        self.assertNotEqual(_expiry(stored), "expired")

    def test_a_sanitised_export_carries_none_of_what_the_panel_holds(self):
        # The whole point of the scrub, against the real schema rather than a
        # fixture written from memory: everything that identifies or
        # authenticates anyone is planted, the export is scrubbed, and the
        # bytes are searched.
        import sqlite3
        import tempfile
        from pathlib import Path

        inline_key_line = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCintegration"
        tls_inbound = dict(
            VISION_INBOUND,
            remark="integration-tls",
            port=24445,
            streamSettings=json.dumps(
                {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            {
                                "certificate": ["-----BEGIN CERTIFICATE-----", "MIIC"],
                                "key": ["-----BEGIN PRIVATE KEY-----", inline_key_line],
                            }
                        ]
                    },
                }
            ),
        )
        created = self.client.post("inbounds/add", body=tls_inbound)
        tls_id = (created or {}).get("id")
        self.assertIsNotNone(tls_id)
        self.addCleanup(lambda: self.client.post(f"inbounds/del/{tls_id}"))

        email = "it-scrub-Relative"
        self.addCleanup(self._delete, email)
        self._add_client(email)
        uuid = self._read(email)["uuid"]

        raw = self.client.download("server/getDb")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x-ui.db"
            path.write_bytes(raw)
            connection = sqlite3.connect(path)
            try:
                (admin_hash,) = connection.execute("SELECT password FROM users LIMIT 1").fetchone()
                (token_hash,) = connection.execute("SELECT token FROM api_tokens LIMIT 1").fetchone()
                columns = {row[1] for row in connection.execute("PRAGMA table_info(clients)")}
            finally:
                connection.close()
            # The lists in db.py were written against this schema; the moment a
            # column they name is gone, the scrub silently does less.
            self.assertTrue(
                {"wg_private_key", "wg_pre_shared_key", "uuid", "sub_id"} <= columns,
                f"clients schema moved: {sorted(columns)}",
            )

            credentials = db_cmd.collect_credentials(path)
            for planted in (uuid, admin_hash, token_hash, inline_key_line):
                self.assertIn(planted, credentials, "the scrub does not know about this value")
            db_cmd.sanitise(path)
            problems = db_cmd.verify_sanitised(path, credentials)
            self.assertEqual(problems, [], "the check found something on the real schema")

            blob = path.read_bytes()
            for planted in (uuid, admin_hash, token_hash, inline_key_line, "it-scrub-Relative"):
                self.assertNotIn(planted.encode(), blob, f"{planted[:12]}… survived the scrub")

    def test_settings_round_trip_without_losing_the_rest(self):
        from lib.commands import panel as panel_cmd

        before = panel_cmd._reader(self.client)()
        applied = apply_and_verify(
            panel_cmd._reader(self.client),
            panel_cmd._writer(self.client),
            {"subTitle": "integration"},
        )
        after = panel_cmd._reader(self.client)()
        self.assertEqual(set(applied.changed), {"subTitle"})
        # Everything else survived a write of all ~112 keys
        self.assertEqual(after["webPort"], before["webPort"])
        self.assertEqual(after["webBasePath"], before["webBasePath"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

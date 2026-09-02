"""Small pure helpers inside the command modules."""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.commands import client as client_cmd
from lib.commands import nodes, panel, sub


class TestExpiry(unittest.TestCase):
    def test_zero_is_never(self):
        self.assertEqual(client_cmd._expiry(0), "never")

    def test_past_is_expired(self):
        self.assertEqual(client_cmd._expiry(int(time.time() * 1000) - 1000), "expired")

    def test_future_is_days(self):
        self.assertTrue(client_cmd._expiry(int(time.time() * 1000) + 10 * 86_400_000).endswith("d"))

    def test_negative_is_a_delayed_start_not_expired(self):
        # The panel stores minus the duration and starts the clock on the
        # first connection. The client can connect; it has not begun.
        self.assertEqual(client_cmd._expiry(-864_000_000), "10d after first use")

    def test_a_string_does_not_crash(self):
        self.assertEqual(client_cmd._expiry("soon"), "never")
        self.assertIsNone(client_cmd._ms_age_days("2026-01-01"))


class TestHeartbeat(unittest.TestCase):
    def test_milliseconds(self):
        age = nodes._heartbeat_age({"lastHeartbeat": int(time.time() * 1000) - 5000})
        assert age is not None
        self.assertAlmostEqual(age, 5, delta=1)

    def test_seconds(self):
        age = nodes._heartbeat_age({"last_heartbeat": int(time.time()) - 5})
        assert age is not None
        self.assertAlmostEqual(age, 5, delta=1)

    def test_rfc3339_string(self):
        # Go serialises time.Time this way; it must not raise.
        age = nodes._heartbeat_age({"lastHeartbeat": "2020-01-01T00:00:00Z"})
        assert age is not None
        self.assertGreater(age, 365 * 86400)

    def test_garbage_is_never(self):
        self.assertIsNone(nodes._heartbeat_age({"lastHeartbeat": "yesterday"}))
        self.assertIsNone(nodes._heartbeat_age({}))


class TestRequirePrivate(unittest.TestCase):
    def test_private_means_any_private_range(self):
        for address in ("10.0.0.5", "192.168.1.9", "172.16.4.4", "100.64.0.9", "fd00::1"):
            self.assertTrue(nodes._inside(address, "private"), address)
        self.assertFalse(nodes._inside("203.0.113.5", "private"))

    def test_a_range_narrows_it(self):
        self.assertTrue(nodes._inside("100.64.0.9", "100.64.0.0/10"))
        self.assertFalse(nodes._inside("10.0.0.5", "100.64.0.0/10"))

    def test_a_name_is_not_an_address(self):
        with self.assertRaises(ValueError):
            nodes._inside("node.example", "private")


class TestFlatten(unittest.TestCase):
    def test_structured_values_travel_as_json(self):
        out = panel._flatten({"a": ["x", "y"], "b": {"k": 1}, "c": True, "d": None, "e": 5})
        self.assertEqual(out, {"a": '["x", "y"]', "b": '{"k": 1}', "c": "true", "d": "", "e": "5"})


class FakeClient:
    def __init__(self, links):
        self.links = links

    def get(self, path, query=None):
        if path.startswith("clients/links/"):
            return self.links
        return [{"email": "alice"}]


class TestLinksFile(unittest.TestCase):
    def test_an_existing_wide_open_file_is_tightened(self):
        # The mode passed to open() applies only to a file being created; an
        # existing 0644 file used to keep its mode while the message said 600.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "links.txt"
            target.write_text("old")
            target.chmod(0o644)
            args = argparse.Namespace(command="links", email="alice", out=str(target), to_stdout=False)
            with contextlib.redirect_stdout(io.StringIO()):
                code = sub.run(args, FakeClient(["vless://link"]))
            self.assertEqual(code, 0)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertIn("vless://link", target.read_text())

    def test_a_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "elsewhere.txt"
            real.write_text("")
            link = Path(directory) / "links.txt"
            os.symlink(real, link)
            args = argparse.Namespace(command="links", email="alice", out=str(link), to_stdout=False)
            with self.assertRaises(OSError):
                sub.run(args, FakeClient(["vless://link"]))
            self.assertEqual(real.read_text(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)

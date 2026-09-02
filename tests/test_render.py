"""Masking, which is the only thing standing between a credential and scrollback.

Output goes to terminals, transcripts and pasted snippets. A UUID printed once
is a UUID distributed, so these check the shape of what leaves rather than
trusting the caller to ask for the right thing.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import render

UUID = "11111111-2222-3333-4444-555555555555"
KEY = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd"


class TestSecretFields(unittest.TestCase):
    def test_credential_fields_do_not_survive(self):
        obj = {
            "id": UUID,
            "password": "test-hunter2hunter2",
            "subId": "subscription-id-value",
            "privateKey": KEY,
            "secret": "test-panelsecret",
            "auth": "authvalue",
        }
        out = json.dumps(render.redact(obj))
        for secret in obj.values():
            self.assertNotIn(secret, out, f"{secret} reached the output")

    def test_innocuous_fields_are_untouched(self):
        obj = {"remark": "SE-exit", "port": 443, "enable": True, "flow": "xtls-rprx-vision"}
        self.assertEqual(render.redact(obj), obj)

    def test_reality_short_ids_and_public_key_are_masked(self):
        obj = {"realitySettings": {"shortIds": ["0123abcd"], "publicKey": KEY, "dest": "a.com:443"}}
        out = json.dumps(render.redact(obj))
        self.assertNotIn(KEY, out)
        self.assertIn("a.com:443", out, "the non-secret dest should stay readable")

    def test_secrets_inside_a_json_string_are_masked(self):
        # Inbound settings arrive as JSON *text*; redacting only the outer object
        # would print every client credential through a field named `settings`.
        obj = {"settings": json.dumps({"clients": [{"id": UUID, "email": "someone"}]})}
        out = json.dumps(render.redact(obj))
        self.assertNotIn(UUID, out)

    def test_nested_structures_are_walked(self):
        obj = {"inbounds": [{"clients": [{"password": "verysecretvalue"}]}]}
        self.assertNotIn("verysecretvalue", json.dumps(render.redact(obj)))

    def test_reveal_is_the_only_way_out(self):
        obj = {"id": UUID}
        self.assertEqual(render.redact(obj, reveal=True), obj)

    def test_dumps_masks_by_default(self):
        self.assertNotIn(UUID, render.dumps({"id": UUID}))
        self.assertIn(UUID, render.dumps({"id": UUID}, reveal=True))

    def test_inline_tls_key_is_masked_whole(self):
        # A PEM key is stored as a list of lines under a key called `key`.
        obj = {"tlsSettings": {"certificates": [{"key": ["-----BEGIN PRIVATE KEY-----", KEY]}]}}
        out = json.dumps(render.redact(obj))
        self.assertNotIn(KEY, out)
        self.assertNotIn("BEGIN PRIVATE", out)

    def test_socks_account_password_is_masked(self):
        # Xray spells it `pass`, not `password`.
        obj = {"users": [{"user": "u", "pass": "sockspassword1"}]}
        self.assertNotIn("sockspassword1", json.dumps(render.redact(obj)))

    def test_numeric_row_ids_are_not_masked(self):
        # `id` is a UUID on a client inside inbound settings, a row number on
        # an inbound or a node. Masking the number makes --json useless.
        self.assertEqual(render.redact({"id": 7}), {"id": 7})
        self.assertNotEqual(render.redact({"id": UUID}), {"id": UUID})


class TestMask(unittest.TestCase):
    def test_short_secrets_reveal_nothing(self):
        self.assertEqual(render.mask("hunter2"), "***")
        self.assertEqual(render.mask("12345678"), "***")

    def test_reveal_is_proportional_not_fixed(self):
        # A fixed prefix of four plus a suffix of two gave away two thirds of a
        # nine-character password. At most a sixth may show.
        for secret in ("hunter123", "Passw0rd!!", "shadowsocks1", KEY, UUID):
            masked = render.mask(secret)
            shown = masked.split("…")[0]
            self.assertLessEqual(len(shown), len(secret) // 6, secret)
            self.assertTrue(secret.startswith(shown))
            self.assertNotIn(secret[-2:], masked.split("(")[0][len(shown):])

    def test_a_uuid_still_has_a_recognisable_prefix(self):
        self.assertTrue(render.mask(UUID).startswith("111111"))

    def test_a_list_masks_to_a_count(self):
        self.assertEqual(render.mask(["a", "b"]), "[2 line(s), masked]")


class TestLabels(unittest.TestCase):
    def test_a_label_degrades_to_a_stub_not_to_nothing(self):
        # Personal data, but also the only handle an operator has on a row.
        masked = render.mask_label("Artemiy")
        self.assertNotEqual(masked, "Artemiy")
        self.assertTrue(masked.startswith("Art"))

    def test_different_labels_stay_different(self):
        self.assertNotEqual(render.mask_label("Dad"), render.mask_label("Mom"))

    def test_very_short_labels_reveal_nothing(self):
        self.assertEqual(render.mask_label("Jo"), "**")

    def test_email_is_masked_in_structures(self):
        out = json.dumps(render.redact({"email": "Grandmother"}))
        self.assertNotIn("Grandmother", out)


class TestFormatting(unittest.TestCase):
    def test_bytes_are_human_readable(self):
        self.assertEqual(render.human_bytes(0), "0 B")
        self.assertEqual(render.human_bytes(1536), "1.5 KiB")
        self.assertIn("GiB", render.human_bytes(5 * 1024**3))

    def test_table_survives_missing_and_empty_values(self):
        rows = [{"a": 1, "b": None}, {"a": None, "b": "x"}]
        out = render.table(rows, ["a", "b"])
        self.assertIn("a", out)
        self.assertIn("x", out)

    def test_empty_table_says_so(self):
        self.assertEqual(render.table([], ["a"]), "(nothing)")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""The mutation guard, against panels that behave badly on purpose.

Each fake panel below reproduces something the real one does. A test that only
proved the happy path would pass against a panel that silently erases half the
object, which is the failure this module exists to catch.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.snapshot import MutationError, apply_and_verify, diff


class FakePanel:
    """Stores one object and applies writes literally, like the real endpoint."""

    def __init__(self, obj: dict):
        self.obj = dict(obj)
        self.writes: list[dict] = []

    def read(self) -> dict:
        return dict(self.obj)

    def write(self, obj: dict) -> None:
        self.writes.append(dict(obj))
        self.obj = dict(obj)


class DroppingPanel(FakePanel):
    """Clears a field on every write, the way flow is cleared on a client update."""

    def __init__(self, obj: dict, drop: str):
        super().__init__(obj)
        self.drop = drop

    def write(self, obj: dict) -> None:
        self.writes.append(dict(obj))
        stored = dict(obj)
        stored[self.drop] = ""
        self.obj = stored


class RegeneratingPanel(FakePanel):
    """Mints a new subscription id on write, invalidating every issued link."""

    def write(self, obj: dict) -> None:
        self.writes.append(dict(obj))
        stored = dict(obj)
        stored["subId"] = "regenerated-by-the-panel"
        self.obj = stored


class IgnoringPanel(FakePanel):
    """Accepts the write and keeps its old value."""

    def write(self, obj: dict) -> None:
        self.writes.append(dict(obj))


CLIENT = {
    "email": "someone",
    "enable": True,
    "flow": "xtls-rprx-vision",
    "subId": "original-sub-id",
    "totalGB": 0,
    "updatedAt": 1000,
}


class TestDiff(unittest.TestCase):
    def test_reserialised_json_text_is_not_a_change(self):
        before = {"settings": '{"a": 1, "b": 2}'}
        after = {"settings": '{\n  "b": 2,\n  "a": 1\n}'}
        self.assertFalse(diff(before, after))

    def test_real_change_inside_json_text_is_seen(self):
        before = {"settings": '{"mtu": 1380}'}
        after = {"settings": '{"mtu": 1420}'}
        self.assertTrue(diff(before, after))

    def test_ignored_fields_are_skipped(self):
        self.assertFalse(diff({"updatedAt": 1}, {"updatedAt": 2}, ignore={"updatedAt"}))


class TestApplyAndVerify(unittest.TestCase):
    def test_intended_change_lands(self):
        panel = FakePanel(CLIENT)
        applied = apply_and_verify(panel.read, panel.write, {"totalGB": 5_000_000})
        self.assertEqual(set(applied.changed), {"totalGB"})
        self.assertEqual(panel.obj["flow"], "xtls-rprx-vision")

    def test_whole_object_is_sent_not_just_the_change(self):
        panel = FakePanel(CLIENT)
        apply_and_verify(panel.read, panel.write, {"totalGB": 1})
        sent = panel.writes[0]
        # The endpoint replaces rather than patches, so a partial body would
        # erase everything it omits.
        self.assertEqual(sent["flow"], "xtls-rprx-vision")
        self.assertEqual(sent["subId"], "original-sub-id")
        self.assertIs(sent["enable"], True)

    def test_dropped_flow_is_refused(self):
        panel = DroppingPanel(CLIENT, drop="flow")
        with self.assertRaises(MutationError) as caught:
            apply_and_verify(panel.read, panel.write, {"totalGB": 1})
        message = str(caught.exception)
        self.assertIn("flow", message)
        # The requested change must not survive a refused write.
        self.assertEqual(panel.obj["totalGB"], 0)

    def test_unrestorable_field_is_reported_not_glossed_over(self):
        # This panel clears flow on *every* write, rollback included, so the
        # tool must say the object could not be fully restored rather than
        # report a clean rollback.
        panel = DroppingPanel(CLIENT, drop="flow")
        with self.assertRaises(MutationError) as caught:
            apply_and_verify(panel.read, panel.write, {"totalGB": 1})
        self.assertIn("ROLLBACK INCOMPLETE", str(caught.exception))

    def test_clean_rollback_says_so(self):
        class OnceOnly(FakePanel):
            """Mangles the first write, behaves on the second."""

            def __init__(self, obj):
                super().__init__(obj)
                self.calls = 0

            def write(self, obj):
                self.calls += 1
                self.writes.append(dict(obj))
                stored = dict(obj)
                if self.calls == 1:
                    stored["flow"] = ""
                self.obj = stored

        panel = OnceOnly(CLIENT)
        with self.assertRaises(MutationError) as caught:
            apply_and_verify(panel.read, panel.write, {"totalGB": 1})
        self.assertIn("rolled back", str(caught.exception))
        self.assertNotIn("INCOMPLETE", str(caught.exception))
        self.assertEqual(panel.obj["flow"], "xtls-rprx-vision")
        self.assertEqual(panel.obj["totalGB"], 0)

    def test_disabled_client_is_refused(self):
        panel = DroppingPanel(CLIENT, drop="enable")
        with self.assertRaises(MutationError) as caught:
            apply_and_verify(panel.read, panel.write, {"totalGB": 1})
        self.assertIn("enable", str(caught.exception))

    def test_regenerated_sub_id_is_refused(self):
        panel = RegeneratingPanel(CLIENT)
        with self.assertRaises(MutationError) as caught:
            apply_and_verify(panel.read, panel.write, {"totalGB": 1})
        self.assertIn("subId", str(caught.exception))

    def test_silently_ignored_write_is_refused(self):
        panel = IgnoringPanel(CLIENT)
        with self.assertRaises(MutationError) as caught:
            apply_and_verify(panel.read, panel.write, {"totalGB": 999})
        self.assertIn("did not apply", str(caught.exception))

    def test_timestamp_churn_is_tolerated(self):
        class Touching(FakePanel):
            def write(self, obj):
                self.writes.append(dict(obj))
                stored = dict(obj)
                stored["updatedAt"] = 2000
                self.obj = stored

        panel = Touching(CLIENT)
        apply_and_verify(panel.read, panel.write, {"totalGB": 7})
        self.assertEqual(panel.obj["totalGB"], 7)

    def test_rollback_failure_is_reported_with_both_causes(self):
        class Stuck(DroppingPanel):
            def __init__(self, obj):
                super().__init__(obj, drop="flow")
                self.calls = 0

            def write(self, obj):
                self.calls += 1
                if self.calls > 1:
                    raise RuntimeError("panel went away")
                super().write(obj)

        panel = Stuck(CLIENT)
        with self.assertRaises(MutationError) as caught:
            apply_and_verify(panel.read, panel.write, {"totalGB": 1})
        message = str(caught.exception)
        self.assertIn("ROLLBACK FAILED", message)
        self.assertIn("panel went away", message)


class TestNestedSettings(unittest.TestCase):
    def test_editing_json_text_field_verifies_by_meaning(self):
        obj = {"id": 1, "settings": json.dumps({"mtu": 1380, "peers": []})}
        panel = FakePanel(obj)
        new_settings = json.dumps({"peers": [], "mtu": 1420}, indent=2)
        applied = apply_and_verify(panel.read, panel.write, {"settings": new_settings})
        self.assertEqual(set(applied.changed), {"settings"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

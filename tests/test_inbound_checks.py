"""Inbound invariants, each against the shape that violates it.

The split between a problem and a note is itself under test: a spare inbound
with no peers must not read as broken, or the check becomes noise and stops
being run at all.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.inbound_checks import check_inbound  # noqa: E402


def reality_inbound(**overrides) -> dict:
    reality = {
        "privateKey": "key",
        "dest": "example.com:443",
        "serverNames": ["example.com"],
        "shortIds": ["ab"],
        "minClientVer": "1.8.0",
    }
    reality.update(overrides.pop("reality", {}))
    inbound = {
        "remark": "SE-exit",
        "protocol": "vless",
        "settings": json.dumps({"clients": []}),
        "streamSettings": json.dumps({"security": "reality", "realitySettings": reality}),
        "sniffing": json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"]}),
    }
    inbound.update(overrides)
    return inbound


def wireguard_inbound(**overrides) -> dict:
    settings = {
        "secretKey": "serverkey",
        "mtu": 1380,
        "peers": [{"allowedIPs": ["10.0.0.2/32"]}],
    }
    settings.update(overrides.pop("settings", {}))
    inbound = {
        "remark": "RU-wg",
        "protocol": "wireguard",
        "settings": json.dumps(settings),
        "streamSettings": json.dumps({}),
        "sniffing": json.dumps({"enabled": False, "destOverride": []}),
    }
    inbound.update(overrides)
    return inbound


class TestHealthy(unittest.TestCase):
    def test_a_correct_reality_inbound_is_clean(self):
        problems, notes = check_inbound(reality_inbound())
        self.assertEqual(problems, [])
        self.assertEqual(notes, [])

    def test_a_correct_wireguard_inbound_is_clean(self):
        problems, _ = check_inbound(wireguard_inbound())
        self.assertEqual(problems, [])

    def test_settings_may_arrive_decoded(self):
        # The list endpoint returns objects while get returns JSON text.
        inbound = reality_inbound()
        inbound["streamSettings"] = json.loads(inbound["streamSettings"])
        problems, _ = check_inbound(inbound)
        self.assertEqual(problems, [])


class TestSniffing(unittest.TestCase):
    def test_missing_quic_is_a_problem(self):
        inbound = reality_inbound(
            sniffing=json.dumps({"enabled": True, "destOverride": ["http", "tls"]})
        )
        problems, _ = check_inbound(inbound)
        self.assertTrue(any("quic" in p for p in problems))

    def test_sniffing_off_is_a_note_not_a_problem(self):
        inbound = reality_inbound(sniffing=json.dumps({"enabled": False, "destOverride": []}))
        problems, notes = check_inbound(inbound)
        self.assertEqual(problems, [])
        self.assertTrue(any("sniffing is off" in n for n in notes))

    def test_wireguard_is_not_judged_on_sniffing(self):
        # It does not route by name, so sniffing says nothing about it.
        _, notes = check_inbound(wireguard_inbound())
        self.assertFalse(any("sniffing" in n for n in notes))


class TestReality(unittest.TestCase):
    def test_missing_private_key(self):
        problems, _ = check_inbound(reality_inbound(reality={"privateKey": ""}))
        self.assertTrue(any("privateKey" in p for p in problems))

    def test_missing_dest_and_names(self):
        problems, _ = check_inbound(reality_inbound(reality={"dest": "", "serverNames": []}))
        self.assertTrue(any("dest" in p for p in problems))
        self.assertTrue(any("serverNames" in p for p in problems))

    def test_min_client_typo_is_caught(self):
        inbound = reality_inbound()
        stream = json.loads(inbound["streamSettings"])
        del stream["realitySettings"]["minClientVer"]
        stream["realitySettings"]["minClient"] = "1.8.0"
        inbound["streamSettings"] = json.dumps(stream)
        problems, _ = check_inbound(inbound)
        self.assertTrue(any("minClientVer" in p for p in problems))

    def test_case_only_misspelling_is_caught(self):
        inbound = reality_inbound()
        stream = json.loads(inbound["streamSettings"])
        stream["realitySettings"]["minclientver"] = "1.8.0"
        del stream["realitySettings"]["minClientVer"]
        inbound["streamSettings"] = json.dumps(stream)
        problems, _ = check_inbound(inbound)
        self.assertTrue(any("minclientver" in p for p in problems))


class TestFinalMask(unittest.TestCase):
    def test_capitalised_final_mask_never_reaches_the_link(self):
        inbound = reality_inbound()
        stream = json.loads(inbound["streamSettings"])
        stream["finalMask"] = "1"
        inbound["streamSettings"] = json.dumps(stream)
        problems, _ = check_inbound(inbound)
        self.assertTrue(any("finalmask" in p for p in problems))

    def test_lowercase_final_mask_is_fine(self):
        inbound = reality_inbound()
        stream = json.loads(inbound["streamSettings"])
        stream["finalmask"] = "1"
        inbound["streamSettings"] = json.dumps(stream)
        problems, _ = check_inbound(inbound)
        self.assertEqual(problems, [])


class TestWireGuard(unittest.TestCase):
    def test_missing_server_key_takes_the_whole_node_down(self):
        problems, _ = check_inbound(wireguard_inbound(settings={"secretKey": ""}))
        self.assertTrue(any("secretKey" in p for p in problems))
        self.assertTrue(any("every inbound" in p or "entire" in p for p in problems))

    def test_duplicate_tunnel_address_within_one_inbound(self):
        inbound = wireguard_inbound(
            settings={
                "peers": [
                    {"allowedIPs": ["10.0.0.2/32"]},
                    {"allowedIPs": ["10.0.0.2/32"]},
                ]
            }
        )
        problems, _ = check_inbound(inbound)
        self.assertTrue(any("both claim tunnel address" in p for p in problems))

    def test_no_peers_is_a_note(self):
        # A spare inbound is a deliberate thing, not a defect.
        problems, notes = check_inbound(wireguard_inbound(settings={"peers": []}))
        self.assertEqual(problems, [])
        self.assertTrue(any("no peers" in n for n in notes))

    def test_missing_mtu_is_a_note(self):
        problems, notes = check_inbound(wireguard_inbound(settings={"mtu": 0}))
        self.assertEqual(problems, [])
        self.assertTrue(any("MTU" in n for n in notes))


if __name__ == "__main__":
    unittest.main(verbosity=2)

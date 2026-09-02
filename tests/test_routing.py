"""Routing invariants, each tested against the config that violates it.

Every rule below describes a real failure mode: the config stays valid, the
panel stays green, and the traffic goes somewhere else. A check for one of them
is only worth having if it fires on the broken shape, so each invariant gets a
config that breaks it and one that does not.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.commands.routing import check_rules

OUTBOUNDS = [{"tag": "direct"}, {"tag": "blocked"}, {"tag": "to-se"}]


def template(rules: list[dict], outbounds=None) -> dict:
    return {"outbounds": outbounds if outbounds is not None else OUTBOUNDS,
            "routing": {"rules": rules}}


HEALTHY = [
    {"inboundTag": ["api"], "outboundTag": "api"},
    {"outboundTag": "blocked", "ip": ["geoip:private", "100.64.0.0/10"]},
    {"outboundTag": "direct", "domain": ["geosite:category-ru"]},
    {"outboundTag": "direct", "ip": ["geoip:ru"]},
    {"outboundTag": "to-se", "network": "tcp,udp"},
]


class TestHealthy(unittest.TestCase):
    def test_a_correct_chain_passes(self):
        problems, _ = check_rules(template(HEALTHY), ["to-se"])
        self.assertEqual(problems, [])


class TestInvariants(unittest.TestCase):
    def test_domain_and_ip_in_one_rule_matches_nothing(self):
        rules = list(HEALTHY)
        rules[2] = {"outboundTag": "direct", "domain": ["geosite:category-ru"], "ip": ["geoip:ru"]}
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("AND together" in p for p in problems))

    def test_api_rule_must_come_first(self):
        rules = [HEALTHY[1], HEALTHY[0]] + HEALTHY[2:]
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("api rule is at position" in p for p in problems))

    def test_missing_api_rule_is_only_a_note(self):
        problems, notes = check_rules(template(HEALTHY[1:]))
        self.assertEqual(problems, [])
        self.assertTrue(any("api" in n for n in notes))

    def test_private_block_without_the_tailnet_range(self):
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "blocked", "ip": ["geoip:private"]}
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("100.64.0.0/10" in p for p in problems))

    def test_private_range_routed_direct_is_not_a_block(self):
        # The rule names geoip:private, so a check that only looks for the
        # name passes it. It sends the traffic on, which is the opposite.
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "direct", "ip": ["geoip:private", "100.64.0.0/10"]}
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("does not drop traffic" in p for p in problems), problems)

    def test_a_blackhole_outbound_counts_as_a_block_whatever_its_tag(self):
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "sink", "ip": ["geoip:private", "100.64.0.0/10"]}
        outbounds = OUTBOUNDS + [{"tag": "sink", "protocol": "blackhole"}]
        problems, _ = check_rules(template(rules, outbounds))
        self.assertEqual(problems, [])

    def test_tailnet_requirement_can_be_changed_or_dropped(self):
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "blocked", "ip": ["geoip:private", "10.8.0.0/16"]}
        problems, _ = check_rules(template(rules), tailnet="10.8.0.0/16")
        self.assertEqual(problems, [])
        problems, _ = check_rules(template(rules), tailnet="none")
        self.assertEqual(problems, [])
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("100.64.0.0/10" in p for p in problems))

    def test_no_private_block_at_all(self):
        rules = [r for r in HEALTHY if "geoip:private" not in (r.get("ip") or [])]
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("geoip:private" in p for p in problems))

    def test_rule_pointing_at_an_undeclared_outbound(self):
        rules = list(HEALTHY)
        rules[-1] = {"outboundTag": "to-frankfurt", "network": "tcp"}
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("to-frankfurt" in p for p in problems))

    def test_api_tag_is_not_reported_as_dangling(self):
        # `api` is served by the gRPC handler, never declared as an outbound.
        problems, _ = check_rules(template(HEALTHY))
        self.assertFalse(any("'api'" in p for p in problems))

    def test_local_rule_below_a_transit_rule_never_fires(self):
        rules = [
            HEALTHY[0],
            HEALTHY[1],
            {"outboundTag": "to-se", "network": "tcp,udp"},
            {"outboundTag": "direct", "ip": ["geoip:ru"]},
        ]
        problems, _ = check_rules(template(rules), ["to-se"])
        self.assertTrue(any("never fires" in p for p in problems))

    def test_ordering_check_is_skipped_when_the_tag_is_absent(self):
        problems, notes = check_rules(template(HEALTHY), ["to-frankfurt"])
        self.assertEqual(problems, [])
        self.assertTrue(any("to-frankfurt" in n for n in notes))

    def test_naming_a_local_tag_as_transit_is_refused_not_answered(self):
        problems, notes = check_rules(template(HEALTHY), ["direct"])
        self.assertEqual(problems, [])
        self.assertTrue(any("cannot compare it to itself" in n for n in notes))

    def test_empty_routing_fails_loudly(self):
        problems, _ = check_rules(template([]))
        self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main(verbosity=2)

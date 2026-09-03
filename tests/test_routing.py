"""Routing invariants, each tested against the config that violates it.

Every rule below describes a real failure mode: the config stays valid, the
panel stays green, and the traffic goes somewhere else. A check for one of them
is only worth having if it fires on the broken shape, so each invariant gets a
config that breaks it and one that does not.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.api import ApiError
from lib.commands import routing
from lib.commands.routing import (
    check_rules,
    default_outbound,
    geodata_problems,
    geodata_tokens,
    parse_probe,
    probe_verdict,
    read_probes,
)

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
        rules = [HEALTHY[1], HEALTHY[0], *HEALTHY[2:]]
        problems, _ = check_rules(template(rules))
        self.assertTrue(any("api rule is at position" in p for p in problems))

    def test_missing_api_rule_is_only_a_note(self):
        problems, notes = check_rules(template(HEALTHY[1:]))
        self.assertEqual(problems, [])
        self.assertTrue(any("api" in n for n in notes))

    def test_geoip_private_alone_is_enough(self):
        # geoip:private already contains 100.64.0.0/10, so a block that names
        # only the category is complete; asking for the range was noise.
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "blocked", "ip": ["geoip:private"]}
        problems, _ = check_rules(template(rules))
        self.assertEqual(problems, [])

    def test_private_range_routed_somewhere_is_a_note_not_a_block(self):
        # The rule names geoip:private, so a check that only looks for the
        # name would call it a block. It sends the traffic on, which may be
        # deliberate, so it is shown rather than failed.
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "direct", "ip": ["geoip:private", "100.64.0.0/10"]}
        problems, notes = check_rules(template(rules))
        self.assertEqual(problems, [])
        self.assertTrue(any("sends geoip:private to 'direct'" in n for n in notes), notes)

    def test_any_rule_with_no_outbound_is_a_problem(self):
        # Not a block anyone wrote: Xray drops the connection with a warning,
        # and older cores routed it to the first outbound. True of every rule,
        # not only the private one.
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "", "ip": ["geoip:private"]}
        rules[3] = {"ip": ["geoip:ru"]}
        problems, _ = check_rules(template(rules))
        self.assertEqual(sum("names no outbound" in p for p in problems), 2, problems)

    def test_a_blackhole_outbound_counts_as_a_block_whatever_its_tag(self):
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "sink", "ip": ["geoip:private", "100.64.0.0/10"]}
        outbounds = [*OUTBOUNDS, {"tag": "sink", "protocol": "blackhole"}]
        problems, _ = check_rules(template(rules, outbounds))
        self.assertEqual(problems, [])

    def test_a_range_outside_geoip_private_can_be_required(self):
        rules = list(HEALTHY)
        rules[1] = {"outboundTag": "blocked", "ip": ["geoip:private"]}
        problems, _ = check_rules(template(rules), require_blocked=["203.0.113.0/24"])
        self.assertTrue(any("203.0.113.0/24" in p for p in problems))
        rules[1] = {"outboundTag": "blocked", "ip": ["geoip:private", "203.0.113.0/24"]}
        problems, _ = check_rules(template(rules), require_blocked=["203.0.113.0/24"])
        self.assertEqual(problems, [])

    def test_no_private_block_at_all_is_a_note(self):
        # Removing the template's block may be what the operator wants; it is
        # shown with its consequence, not failed.
        rules = [r for r in HEALTHY if "geoip:private" not in (r.get("ip") or [])]
        problems, notes = check_rules(template(rules))
        self.assertEqual(problems, [])
        self.assertTrue(any("no rule mentions geoip:private" in n for n in notes), notes)

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


class TestDefaultOutbound(unittest.TestCase):
    def test_the_first_outbound_is_where_unmatched_traffic_goes(self):
        # Not "direct": on a transit node the first outbound is the tunnel, so
        # "no rule matched" means abroad.
        self.assertEqual(default_outbound({"outbounds": [{"tag": "to-se"}, {"tag": "direct"}]}), "to-se")

    def test_an_untagged_outbound_is_skipped(self):
        self.assertEqual(default_outbound({"outbounds": [{}, {"tag": "direct"}]}), "direct")

    def test_no_outbounds_says_so_rather_than_guessing(self):
        self.assertIn("no outbound", default_outbound({}))


class TestProbes(unittest.TestCase):
    def test_a_bare_destination_carries_no_expectation(self):
        self.assertEqual(parse_probe("ifconfig.me"), ("domain", "ifconfig.me", None))

    def test_an_expectation_is_split_off(self):
        self.assertEqual(parse_probe("ifconfig.me=blocked"), ("domain", "ifconfig.me", "blocked"))

    def test_an_address_is_probed_as_an_ip_not_a_domain(self):
        # The core matches ip: rules against one field and domain: rules against
        # another, so sending an address as a domain tests the wrong half.
        self.assertEqual(parse_probe("1.1.1.1=direct"), ("ip", "1.1.1.1", "direct"))
        self.assertEqual(parse_probe("2606:4700::1111")[0], "ip")

    def test_a_probe_with_no_destination_is_refused(self):
        with self.assertRaises(ValueError):
            parse_probe("=blocked")

    def test_comments_and_blank_lines_are_dropped(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("# resolvers\nifconfig.me=blocked\n\ngithub.com=direct  # control\n")
            name = handle.name
        try:
            self.assertEqual(read_probes(name), ["ifconfig.me=blocked", "github.com=direct"])
        finally:
            os.unlink(name)


class TestProbeVerdict(unittest.TestCase):
    def test_a_matched_rule_reports_its_outbound(self):
        self.assertEqual(
            probe_verdict({"matched": True, "outboundTag": "blocked"}, "direct", "blocked"),
            ("blocked", True, True),
        )

    def test_no_match_falls_through_to_the_default_outbound(self):
        outbound, matched, ok = probe_verdict({"matched": False}, "to-se", None)
        self.assertEqual((outbound, matched), ("to-se", False))
        self.assertTrue(ok)

    def test_an_unmet_expectation_is_not_ok(self):
        self.assertFalse(probe_verdict({"matched": False}, "direct", "blocked")[2])

    def test_an_empty_answer_does_not_crash(self):
        self.assertEqual(probe_verdict({}, "direct", None)[0], "direct")


class TestGeodataTokens(unittest.TestCase):
    def test_literals_are_not_database_lookups(self):
        rules = [
            {
                "outboundTag": "blocked",
                "domain": [
                    "geosite:category-ip-geo-detect",
                    "domain:iplogger.org",
                    "full:checkip.amazonaws.com",
                    "regexp:.*\\.ru$",
                    "keyword:speedtest",
                    "example.com",
                ],
            }
        ]
        site, addresses = geodata_tokens(template(rules))
        self.assertEqual(site, ["geosite:category-ip-geo-detect"])
        self.assertEqual(addresses, [])

    def test_ip_side_picks_geoip_and_ext_but_not_cidrs(self):
        rules = [{"outboundTag": "blocked", "ip": ["geoip:private", "100.64.0.0/10", "ext:geoip_RU.dat:ru"]}]
        _, addresses = geodata_tokens(template(rules))
        self.assertEqual(addresses, ["ext:geoip_RU.dat:ru", "geoip:private"])

    def test_a_domain_given_as_a_bare_string_is_still_read(self):
        site, _ = geodata_tokens(template([{"outboundTag": "blocked", "domain": "geosite:cn"}]))
        self.assertEqual(site, ["geosite:cn"])


class TestGeodataProblems(unittest.TestCase):
    def test_an_unresolvable_category_is_a_problem_not_a_note(self):
        problems = geodata_problems(
            [{"token": "geosite:category-ip-geo-detekt", "reason": "categoryMissing", "file": "geosite.dat"}]
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("category-ip-geo-detekt", problems[0])
        self.assertIn("refuses the config", problems[0])

    def test_nothing_unresolvable_is_no_problem(self):
        self.assertEqual(geodata_problems([]), [])
        self.assertEqual(geodata_problems(None), [])


class FakePanel:
    """Answers the three endpoints `routing` uses, and records what it was asked."""

    def __init__(self, template, validate=None, route=None):
        self.template = template
        self.validate = validate or []
        self.route = route or {}
        self.asked = []

    def post(self, path, body=None, form=None, query=None):
        self.asked.append((path, form))
        if path == "xray/":
            return {"xraySetting": self.template, "outboundTestUrl": "https://example.invalid/204"}
        if path == "xray/geodata/validate":
            return self.validate
        if path == "xray/routeTest":
            return self.route
        raise AssertionError(f"unexpected path {path}")


def args(**fields):
    return argparse.Namespace(
        direct_before=None, require_blocked=[], full=False, json=False, reveal=False, **fields
    )


class TestCheckWiring(unittest.TestCase):
    TEMPLATE = template(
        [
            {"inboundTag": ["api"], "outboundTag": "api"},
            {"outboundTag": "blocked", "ip": ["geoip:private"]},
            {"outboundTag": "blocked", "domain": ["geosite:category-ip-geo-detekt"]},
        ]
    )

    def run_check(self, panel):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = routing.run(args(command="check"), panel)
        return code, out.getvalue()

    def test_an_unresolvable_category_turns_the_check_red(self):
        panel = FakePanel(
            self.TEMPLATE,
            validate=[{"token": "geosite:category-ip-geo-detekt", "reason": "categoryMissing",
                       "file": "geosite.dat"}],
        )
        code, output = self.run_check(panel)
        self.assertEqual(code, 1)
        self.assertIn("category-ip-geo-detekt", output)

    def test_resolvable_tokens_leave_the_check_green(self):
        code, output = self.run_check(FakePanel(self.TEMPLATE, validate=[]))
        self.assertEqual(code, 0)
        self.assertIn("no silent-failure pattern", output)

    def test_only_the_tokens_are_sent_for_validation(self):
        panel = FakePanel(self.TEMPLATE, validate=[])
        self.run_check(panel)
        sent = [form for path, form in panel.asked if path == "xray/geodata/validate"]
        self.assertEqual(
            sent,
            [
                {"kind": "site", "tokens": "geosite:category-ip-geo-detekt"},
                {"kind": "ip", "tokens": "geoip:private"},
            ],
        )

    def test_a_panel_too_old_to_validate_says_so_instead_of_passing_quietly(self):
        class Old(FakePanel):
            def post(self, path, body=None, form=None, query=None):
                if path == "xray/geodata/validate":
                    raise ApiError("HTTP 404")
                return super().post(path, body, form, query)

        code, output = self.run_check(Old(self.TEMPLATE))
        self.assertEqual(code, 0)
        self.assertIn("not validated", output)


class TestTestWiring(unittest.TestCase):
    TEMPLATE = template(
        [{"inboundTag": ["api"], "outboundTag": "api"}, {"outboundTag": "blocked", "ip": ["geoip:private"]}],
        outbounds=[{"tag": "to-se"}, {"tag": "blocked"}],
    )

    def probe(self, spec, route):
        panel = FakePanel(self.TEMPLATE, route=route)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = routing.run(
                args(command="test", probe=[spec], from_file=None, inbound=None, port=443,
                     network="tcp", protocol="tls", email=None),
                panel,
            )
        return code, out.getvalue(), panel

    def test_a_probe_that_lands_where_it_should_exits_zero(self):
        code, output, _ = self.probe("ifconfig.me=blocked", {"matched": True, "outboundTag": "blocked"})
        self.assertEqual(code, 0)
        self.assertIn("ok", output)

    def test_a_probe_that_lands_elsewhere_exits_one(self):
        code, output, _ = self.probe("ifconfig.me=blocked", {"matched": False})
        self.assertEqual(code, 1)
        self.assertIn("MISMATCH", output)

    def test_an_unmatched_probe_names_the_default_outbound_of_this_node(self):
        # Not "direct": this template's first outbound is the transit tunnel.
        _, output, _ = self.probe("github.com", {"matched": False})
        self.assertIn("to-se", output)

    def test_the_destination_is_sent_under_the_field_the_core_matches_on(self):
        _, _, panel = self.probe("1.1.1.1=direct", {"matched": False})
        form = next(form for path, form in panel.asked if path == "xray/routeTest")
        self.assertIn("ip", form)
        self.assertNotIn("domain", form)


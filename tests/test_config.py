"""Where the URL and the token come from, and which pairs are refused.

The dangerous combination is a token from one place and a URL from another:
the token then travels to whatever panel the URL names.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import config

PIN = "ab" * 32


class Registry(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.registry = self.root / "nodes"
        self.registry.mkdir()
        self.secrets = self.root / "secrets"
        self.secrets.mkdir()
        self._patches = [
            mock.patch.dict(os.environ, {"XUI_NODES_DIR": str(self.registry)}, clear=False),
            mock.patch.object(config, "SECRETS_DIR", self.secrets),
        ]
        for patch in self._patches:
            patch.start()
        for variable in ("XUI_URL", "XUI_TOKEN", "XUI_VERIFY_TLS", "XUI_PIN_SHA256", "XUI_ALLOW_PLAINTEXT"):
            os.environ.pop(variable, None)

    def tearDown(self):
        for patch in self._patches:
            patch.stop()
        self.directory.cleanup()

    def node(self, name: str, body: str) -> None:
        path = self.registry / f"{name}.toml"
        path.write_text(body)
        path.chmod(0o600)

    def secret(self, name: str, value: str) -> None:
        path = self.secrets / name
        path.write_text(value)
        path.chmod(0o600)


class TestNodeIsolation(Registry):
    def test_a_node_takes_url_and_token_from_itself(self):
        self.node("se-1", 'panel = "https://se-1.example:2053/base"\ntoken = "node-token"\n')
        panel = config.resolve(node="se-1")
        self.assertEqual(panel.url, "https://se-1.example:2053/base")
        self.assertEqual(panel.token, "node-token")

    def test_environment_url_cannot_redirect_a_node_token(self):
        # XUI_URL left exported in the shell used to win over the node's own
        # address, sending the node's token to whatever panel it named.
        self.node("se-1", 'panel = "https://se-1.example:2053/base"\ntoken = "node-token"\n')
        environment = {"XUI_URL": "https://other.example/x", "XUI_TOKEN": "other"}
        with mock.patch.dict(os.environ, environment), mock.patch.object(config, "warn") as warn:
            panel = config.resolve(node="se-1")
        self.assertEqual(panel.url, "https://se-1.example:2053/base")
        self.assertEqual(panel.token, "node-token")
        self.assertEqual(warn.call_count, 2)

    def test_a_node_without_a_url_does_not_fall_back_to_the_default_panel(self):
        # secrets/url is the default panel; pairing it with se-1's token would
        # send that token to the wrong host.
        self.secret("url", "https://default.example/base")
        self.node("se-1", 'token = "node-token"\n')
        with self.assertRaises(config.ConfigError) as caught:
            config.resolve(node="se-1")
        self.assertIn("se-1", str(caught.exception))

    def test_per_node_secrets_still_apply(self):
        self.node("se-1", "")
        self.secret("url.se-1", "https://se-1.example/base")
        self.secret("token.se-1", "node-token")
        panel = config.resolve(node="se-1")
        self.assertEqual(panel.token, "node-token")

    def test_a_second_panel_needs_no_registry_at_all(self):
        # secrets/url.NAME and secrets/token.NAME are enough to name a panel.
        os.environ.pop("XUI_NODES_DIR", None)
        self.secret("url.home", "https://home.example:2053/base")
        self.secret("token.home", "home-token")
        panel = config.resolve(node="home")
        self.assertEqual(panel.url, "https://home.example:2053/base")
        self.assertEqual(panel.token, "home-token")
        self.assertEqual(panel.name, "home")

    def test_an_unknown_name_says_where_to_put_it(self):
        with self.assertRaises(config.ConfigError) as caught:
            config.resolve(node="nowhere")
        self.assertIn("secrets/url.nowhere", str(caught.exception))

    def test_explicit_flags_win_even_for_a_node(self):
        self.node("se-1", 'panel = "https://se-1.example/base"\ntoken = "node-token"\n')
        panel = config.resolve(node="se-1", url="https://typed.example/base")
        self.assertEqual(panel.url, "https://typed.example/base")

    def test_pin_comes_from_the_node(self):
        self.node("se-1", f'panel = "https://se-1.example/base"\ntoken = "t"\npin_sha256 = "{PIN}"\n')
        self.assertEqual(config.resolve(node="se-1").pin_sha256, PIN)


class TestPlaintext(Registry):
    def test_http_to_a_remote_host_is_refused(self):
        with self.assertRaises(config.ConfigError) as caught:
            config.resolve(url="http://panel.example:2053/base", token="t")
        self.assertIn("clear text", str(caught.exception))

    def test_http_to_loopback_is_fine(self):
        panel = config.resolve(url="http://127.0.0.1:2053", token="t")
        self.assertFalse(panel.allow_plaintext)

    def test_http_with_the_flag_is_allowed(self):
        panel = config.resolve(url="http://panel.example:2053/base", token="t", allow_plaintext=True)
        self.assertEqual(panel.scheme, "http")

    def test_the_flag_can_come_from_the_node_but_not_the_environment_for_a_node(self):
        self.node("lan", 'panel = "http://10.0.0.5:2053/b"\ntoken = "t"\nallow_plaintext = true\n')
        self.assertTrue(config.resolve(node="lan").allow_plaintext)
        self.node("lan2", 'panel = "http://10.0.0.6:2053/b"\ntoken = "t"\n')
        with mock.patch.dict(os.environ, {"XUI_ALLOW_PLAINTEXT": "1"}), self.assertRaises(config.ConfigError):
            config.resolve(node="lan2")


class TestPin(Registry):
    def test_pin_is_normalised(self):
        panel = config.resolve(url="https://p.example/b", token="t", pin_sha256="AB:" * 31 + "AB")
        self.assertEqual(panel.pin_sha256, PIN)

    def test_a_pin_that_is_not_a_sha256_is_refused(self):
        with self.assertRaises(config.ConfigError):
            config.resolve(url="https://p.example/b", token="t", pin_sha256="abcd")

    def test_a_pin_needs_https(self):
        with self.assertRaises(config.ConfigError):
            config.resolve(url="http://127.0.0.1/b", token="t", pin_sha256=PIN)


class TestDisplay(unittest.TestCase):
    def test_display_url_drops_the_base_path(self):
        panel = config.PanelConfig(url="https://p.example:2053/s3cr3t", token="t", verify_tls=False)
        self.assertEqual(panel.display_url, "https://p.example:2053")


if __name__ == "__main__":
    unittest.main(verbosity=2)

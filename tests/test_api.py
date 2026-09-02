"""The HTTP client, against a local server that misbehaves on purpose."""

from __future__ import annotations

import http.server
import sys
import threading
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import api, config


class Handler(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[tuple[str, str, dict]]] = []

    def log_message(self, format, *args):
        pass

    def _reply(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Handler.seen.append(("GET", self.path, dict(self.headers)))
        if self.path.endswith("/redirect"):
            self._reply(302, headers={"Location": "http://127.0.0.1:1/elsewhere/basepath"})
        elif self.path.endswith("/plain"):
            self._reply(200, b'{"success": true, "obj": [1]}')
        elif "/echo/" in self.path:
            self._reply(200, b'{"success": true, "obj": "' + self.path.encode() + b'"}')
        else:
            self._reply(404)

    def do_POST(self):
        Handler.seen.append(("POST", self.path, dict(self.headers)))
        if self.path.endswith("/redirect"):
            self._reply(302, headers={"Location": "http://127.0.0.1:1/elsewhere"})
        else:
            self._reply(200, b'{"success": true, "obj": null}')


class TestClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        port = cls.server.server_address[1]
        cls.client = api.Client(
            config.PanelConfig(url=f"http://127.0.0.1:{port}/basepath", token="tok", verify_tls=False)
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        Handler.seen.clear()

    def test_redirects_are_not_followed(self):
        # urllib copies every header, Authorization included, onto the new
        # request, whatever host it names. So the token stays here.
        with self.assertRaises(api.ApiError) as caught:
            self.client.get("redirect")
        self.assertIn("redirected", str(caught.exception))
        self.assertEqual(len(Handler.seen), 1)
        # The redirect target's path is a base path too; it is not repeated.
        self.assertNotIn("basepath", str(caught.exception).split("to ")[-1])

    def test_a_post_redirect_is_not_turned_into_a_get(self):
        with self.assertRaises(api.ApiError):
            self.client.post("redirect", body={})
        self.assertEqual([m for m, _, _ in Handler.seen], ["POST"])

    def test_path_segments_are_escaped_whole(self):
        # The panel accepts `?` and `#` in a client label. Unescaped, the
        # request addresses a different resource or none.
        result = self.client.get(api.path("echo", "q?x=1#frag"))
        self.assertEqual(result, "/basepath/panel/api/echo/q%3Fx%3D1%23frag")
        self.assertEqual(Handler.seen[0][1], "/basepath/panel/api/echo/q%3Fx%3D1%23frag")

    def test_a_space_in_a_segment_does_not_crash(self):
        self.assertEqual(self.client.get(api.path("echo", "a b")), "/basepath/panel/api/echo/a%20b")

    def test_query_is_encoded_separately(self):
        self.client.post(api.path("clients", "del", "x"), query={"keepTraffic": "1"})
        self.assertEqual(Handler.seen[0][1], "/basepath/panel/api/clients/del/x?keepTraffic=1")

    def test_bearer_and_xhr_headers_are_sent(self):
        self.client.get("plain")
        headers = Handler.seen[0][2]
        self.assertEqual(headers.get("Authorization"), "Bearer tok")
        self.assertEqual(headers.get("X-Requested-With"), "XMLHttpRequest")

    def test_unreachable_message_has_no_base_path(self):
        client = api.Client(
            config.PanelConfig(url="http://127.0.0.1:1/s3cr3tbase", token="tok", verify_tls=False)
        )
        with self.assertRaises(api.ApiError) as caught:
            client.get("plain")
        self.assertNotIn("s3cr3tbase", str(caught.exception))


class TestPin(unittest.TestCase):
    def test_a_mismatched_certificate_is_refused_before_the_request(self):
        der = b"not-the-pinned-cert"
        connection = api._PinnedConnection("127.0.0.1", 1)
        connection.pin = "0" * 64
        fake_socket = mock.Mock()
        fake_socket.getpeercert.return_value = der
        with mock.patch.object(api.http.client.HTTPSConnection, "connect"):
            connection.sock = fake_socket
            with self.assertRaises(api.PinError) as caught:
                connection.connect()
        self.assertIn(api.fingerprint(der), str(caught.exception))
        fake_socket.close.assert_called()

    def test_a_matching_certificate_passes(self):
        der = b"the-pinned-cert"
        connection = api._PinnedConnection("127.0.0.1", 1)
        connection.pin = api.fingerprint(der)
        fake_socket = mock.Mock()
        fake_socket.getpeercert.return_value = der
        with mock.patch.object(api.http.client.HTTPSConnection, "connect"):
            connection.sock = fake_socket
            connection.connect()
        fake_socket.close.assert_not_called()


class TestStripPaths(unittest.TestCase):
    def test_paths_are_dropped_from_urls(self):
        text = 'Get "https://100.64.0.9:2053/abc123/panel/api/x": dial tcp: timeout'
        self.assertEqual(api.strip_paths(text), 'Get "https://100.64.0.9:2053/…": dial tcp: timeout')


if __name__ == "__main__":
    unittest.main(verbosity=2)

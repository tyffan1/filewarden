"""End-to-end CLI test against a local mock of the VirusTotal API.

The CLI talks to ``fwl.client.API_BASE``, so the whole user flow —
key check, per-file hash lookup, upload after confirmation, JSON/CSV
reports — can be exercised offline.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import fwl.client as client_module
from fwl.cli import main
from fwl.scanner import sha256_file

GOOD_KEY = "good-key"
KNOWN_STATS = {"harmless": 60, "undetected": 10}
UPLOAD_ANALYSIS = {"status": "completed", "stats": {"undetected": 71}, "results": {}}


class MockVirusTotalHandler(BaseHTTPRequestHandler):
    db: dict[str, dict] = {}
    uploads: list[bytes] = []

    def log_message(self, *args) -> None:  # keep the test output clean
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if self.headers.get("x-apikey") != GOOD_KEY:
            self._send(401, {"error": {"code": "AuthenticationRequiredError", "message": "bad key"}})
            return False
        return True

    def do_GET(self) -> None:
        if not self._authorized():
            return
        path = urllib.parse.urlparse(self.path).path
        prefix = "/api/v3/files/"
        if path.startswith(prefix):
            digest = path[len(prefix):]
            if digest in type(self).db:
                self._send(200, {"data": {"attributes": type(self).db[digest]}})
            else:
                self._send(404, {"error": {"code": "NotFoundError", "message": "not found"}})
            return
        if path.startswith("/api/v3/analyses/"):
            self._send(200, {"data": {"attributes": UPLOAD_ANALYSIS}})
            return
        self._send(404, {"error": {"code": "NotFoundError", "message": "unknown route"}})

    def do_POST(self) -> None:
        if not self._authorized():
            return
        length = int(self.headers.get("Content-Length", "0"))
        type(self).uploads.append(self.rfile.read(length))
        self._send(200, {"data": {"type": "analysis", "id": "analysis-1"}})


class CliIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockVirusTotalHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.api_base = f"http://127.0.0.1:{cls.server.server_port}/api/v3"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="filewarden-cli-"))
        self.addCleanup(self._cleanup)
        MockVirusTotalHandler.db = {}
        MockVirusTotalHandler.uploads = []

        self.known = self.tmp / "known.bin"
        self.known.write_bytes(b"known content")
        self.unknown = self.tmp / "unknown.bin"
        self.unknown.write_bytes(b"never seen before")
        MockVirusTotalHandler.db[sha256_file(self.known)] = {
            "last_analysis_stats": KNOWN_STATS,
            "last_analysis_results": {},
        }

        self.env = mock.patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": str(self.tmp / "cfg"), "VIRUSTOTAL_API_KEY": ""},
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        patcher = mock.patch.object(client_module, "API_BASE", self.api_base)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _cleanup(self) -> None:
        for path in sorted(self.tmp.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            else:
                path.rmdir()
        self.tmp.rmdir()

    def run_cli(self, *argv: str) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = main(list(argv))
        return code, buffer.getvalue()

    def test_hash_lookup_and_confirmed_upload(self) -> None:
        report = self.tmp / "report.json"
        csv_report = self.tmp / "report.csv"
        code, output = self.run_cli(
            "-k", GOOD_KEY,
            "--rpm", "0",
            "--upload", "always",          # explicit opt-in stand-in for the prompt
            "--json", str(report),
            "--csv", str(csv_report),
            str(self.tmp),
        )

        self.assertEqual(code, 0, output)
        data = json.loads(report.read_text(encoding="utf-8"))
        statuses = {Path(item["path"]).name: item for item in data["results"]}
        self.assertFalse(statuses["known.bin"]["uploaded"])
        self.assertTrue(statuses["unknown.bin"]["uploaded"])
        self.assertEqual(data["summary"]["files"], 2)
        self.assertEqual(len(MockVirusTotalHandler.uploads), 1)
        self.assertIn(b"never seen before", MockVirusTotalHandler.uploads[0])
        self.assertTrue(csv_report.exists())

    def test_threats_lead_to_exit_code_one(self) -> None:
        MockVirusTotalHandler.db[sha256_file(self.known)] = {
            "last_analysis_stats": {"malicious": 7, "undetected": 63},
            "last_analysis_results": {
                "SomeEngine": {"category": "malicious", "engine_name": "SomeEngine", "result": "Trojan.Test"},
            },
        }
        code, output = self.run_cli(
            "-k", GOOD_KEY, "--rpm", "0", "--upload", "never", str(self.known)
        )
        self.assertEqual(code, 1, output)
        self.assertIn("MALICIOUS", output)

    def test_hash_only_mode_never_uploads(self) -> None:
        code, output = self.run_cli(
            "-k", GOOD_KEY, "--rpm", "0", "--upload", "never", str(self.unknown)
        )
        self.assertEqual(code, 0, output)
        self.assertEqual(MockVirusTotalHandler.uploads, [])
        self.assertIn("not in VT", output)

    def test_bad_key_is_reported(self) -> None:
        code, output = self.run_cli(
            "-k", "wrong-key", "--rpm", "0", "--upload", "never", str(self.known)
        )
        self.assertEqual(code, 2)
        self.assertIn("API key", output)


if __name__ == "__main__":
    unittest.main()

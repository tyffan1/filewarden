"""Offline tests for the VirusTotal client (no network access)."""

from __future__ import annotations

import os
import tempfile
import unittest

from fwl.client import EMPTY_FILE_SHA256, VirusTotalClient, encode_multipart
from fwl.errors import (
    ApiKeyError,
    NetworkError,
    QuotaExceededError,
    UnknownHashError,
    UploadError,
)


class FakeClock:
    """Deterministic clock: ``sleep`` moves time forward."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeTransport:
    """Returns queued responses and records every request."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes | None, dict, float]] = []
        self.responses: list = []

    def __call__(self, method, url, body, headers, timeout):
        self.calls.append((method, url, body, dict(headers), timeout))
        if not self.responses:
            raise AssertionError(f"unexpected request: {method} {url}")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_client(transport: FakeTransport, clock: FakeClock, **kwargs) -> VirusTotalClient:
    return VirusTotalClient(
        "test-key",
        transport=transport,
        clock=clock,
        sleep=clock.sleep,
        **kwargs,
    )


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.transport = FakeTransport()

    def test_get_file_report_returns_attributes(self) -> None:
        attributes = {"last_analysis_stats": {"malicious": 1, "undetected": 70}}
        self.transport.responses.append((200, {"data": {"attributes": attributes}}, {}))
        client = make_client(self.transport, self.clock)

        self.assertEqual(client.get_file_report("a" * 64), attributes)
        method, url, _, headers, _ = self.transport.calls[0]
        self.assertEqual(method, "GET")
        self.assertTrue(url.endswith("/files/" + "a" * 64))
        self.assertEqual(headers["x-apikey"], "test-key")

    def test_unknown_hash_raises(self) -> None:
        payload = {"error": {"code": "NotFoundError", "message": "not found"}}
        self.transport.responses.append((404, payload, {}))
        client = make_client(self.transport, self.clock)

        with self.assertRaises(UnknownHashError):
            client.get_file_report("b" * 64)

    def test_bad_key_raises_api_key_error(self) -> None:
        self.transport.responses.append((401, {"error": {"message": "Wrong API key"}}, {}))
        client = make_client(self.transport, self.clock)

        with self.assertRaises(ApiKeyError):
            client.get_file_report("c" * 64)

    def test_empty_key_rejected(self) -> None:
        with self.assertRaises(ApiKeyError):
            VirusTotalClient("   ")

    def test_verify_key_accepts_known_empty_hash(self) -> None:
        self.transport.responses.append((200, {"data": {"attributes": {}}}, {}))
        client = make_client(self.transport, self.clock)

        self.assertTrue(client.verify_key())
        self.assertIn(EMPTY_FILE_SHA256, self.transport.calls[0][1])

    def test_rate_limited_then_success(self) -> None:
        self.transport.responses.append((429, {"error": {"code": "QuotaExceededError"}}, {"Retry-After": "30"}))
        self.transport.responses.append((200, {"data": {"attributes": {"ok": True}}}, {}))
        client = make_client(self.transport, self.clock, max_retries=1)

        client.get_file_report("d" * 64)
        self.assertEqual(len(self.transport.calls), 2)
        self.assertGreaterEqual(self.clock.now, 30.0)

    def test_quota_exceeded_after_retries(self) -> None:
        self.transport.responses.append((429, {"error": {"code": "QuotaExceededError"}}, {}))
        self.transport.responses.append((429, {"error": {"code": "QuotaExceededError"}}, {}))
        client = make_client(self.transport, self.clock, max_retries=1)

        with self.assertRaises(QuotaExceededError):
            client.get_file_report("e" * 64)

    def test_server_error_is_retried(self) -> None:
        self.transport.responses.append((503, {"error": {"message": "unavailable"}}, {}))
        self.transport.responses.append((200, {"data": {"attributes": {}}}, {}))
        client = make_client(self.transport, self.clock, max_retries=1)

        client.get_file_report("f" * 64)
        self.assertEqual(len(self.transport.calls), 2)

    def test_network_error_is_retried(self) -> None:
        self.transport.responses.append(NetworkError("boom"))
        self.transport.responses.append((200, {"data": {"attributes": {}}}, {}))
        client = make_client(self.transport, self.clock, max_retries=1)

        client.get_file_report("1" * 64)
        self.assertEqual(len(self.transport.calls), 2)

    def test_requests_are_paced_by_rate_limiter(self) -> None:
        self.transport.responses.append((200, {"data": {"attributes": {}}}, {}))
        self.transport.responses.append((200, {"data": {"attributes": {}}}, {}))
        client = make_client(self.transport, self.clock, rpm=4)

        client.get_file_report("2" * 64)
        first_moment = self.clock.now
        client.get_file_report("3" * 64)
        self.assertGreaterEqual(self.clock.now - first_moment, 15.0)

    def test_upload_builds_multipart_body(self) -> None:
        payload = b"hello-virus"
        with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as handle:
            handle.write(payload)
            path = handle.name
        self.addCleanup(os.unlink, path)

        self.transport.responses.append((200, {"data": {"type": "analysis", "id": "abc123"}}, {}))
        client = make_client(self.transport, self.clock)

        analysis_id = client.upload_file(path)
        self.assertEqual(analysis_id, "abc123")
        method, url, body, headers, _ = self.transport.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/files"))
        self.assertIn("multipart/form-data; boundary=", headers["Content-Type"])
        boundary = headers["Content-Type"].split("boundary=")[1]
        self.assertIn(f"--{boundary}".encode(), body)
        self.assertIn(payload, body)
        self.assertEqual(headers["Content-Length"], str(len(body)))

    def test_wait_for_analysis_polls_until_completed(self) -> None:
        in_progress = {"data": {"attributes": {"status": "in-progress"}}}
        completed = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {"malicious": 3, "undetected": 69},
                    "results": {"Engine": {"category": "malicious", "result": "Trojan.Test"}},
                }
            }
        }
        self.transport.responses.append((200, in_progress, {}))
        self.transport.responses.append((200, completed, {}))
        client = make_client(self.transport, self.clock)

        attributes = client.wait_for_analysis("an-id", poll_interval=15.0)
        self.assertEqual(attributes["status"], "completed")
        self.assertEqual(len(self.transport.calls), 2)
        self.assertGreaterEqual(self.clock.now, 15.0)

    def test_upload_url_requires_premium(self) -> None:
        self.transport.responses.append(
            (403, {"error": {"code": "ForbiddenError", "message": "forbidden"}}, {})
        )
        client = make_client(self.transport, self.clock)

        with self.assertRaises(UploadError):
            client.get_upload_url()

    def test_multipart_encoder_escapes_filename(self) -> None:
        boundary, body = encode_multipart('evil";\r\nname.bin', b"data")
        self.assertNotIn(b"\r\nname.bin", body.split(b"\r\n\r\n")[0])
        self.assertIn(f"--{boundary}".encode(), body)


if __name__ == "__main__":
    unittest.main()

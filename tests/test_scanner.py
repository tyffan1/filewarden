"""Tests for the hash-first scanning logic."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from fwl.errors import UnknownHashError, UploadError
from fwl.scanner import (
    Decision,
    Scanner,
    Status,
    UploadPolicy,
    collect_files,
    sha256_file,
)


class FakeClient:
    """Duck-typed stand-in for VirusTotalClient."""

    def __init__(self, known: dict | None = None, analysis: dict | None = None):
        self.known = known or {}
        self.analysis = analysis or {
            "status": "completed",
            "stats": {"malicious": 0, "undetected": 72},
            "results": {},
        }
        self.lookups: list[str] = []
        self.uploads: list[str] = []

    def get_file_report(self, sha256, cancel=None):
        self.lookups.append(sha256)
        if sha256 in self.known:
            return self.known[sha256]
        raise UnknownHashError(sha256)

    def upload_file(self, path, cancel=None, on_progress=None):
        self.uploads.append(str(path))
        return "analysis-1"

    def wait_for_analysis(self, analysis_id, *, cancel=None, on_status=None, timeout=900.0,
                          poll_interval=15.0):
        return self.analysis


class ScannerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="filewarden-test-"))
        self.addCleanup(self._cleanup)
        self.file = self.tmp / "sample.bin"
        self.file.write_bytes(b"some simulation data")

    def _cleanup(self) -> None:
        for path in sorted(self.tmp.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            else:
                path.rmdir()
        self.tmp.rmdir()

    def make_scanner(self, client, **kwargs) -> Scanner:
        return Scanner(client, **kwargs)

    # ------------------------------------------------------------------ tests

    def test_sha256_matches_hashlib(self) -> None:
        expected = hashlib.sha256(self.file.read_bytes()).hexdigest()
        self.assertEqual(sha256_file(self.file), expected)

    def test_known_clean_file_is_reported_without_upload(self) -> None:
        digest = sha256_file(self.file)
        client = FakeClient(known={digest: {"last_analysis_stats": {"harmless": 60, "undetected": 5}}})
        scanner = self.make_scanner(client, policy=UploadPolicy.NEVER)

        results = list(scanner.scan([self.tmp]))
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.status, Status.CLEAN)
        self.assertFalse(result.uploaded)
        self.assertEqual(result.engines_total, 65)
        self.assertEqual(client.uploads, [])

    def test_malicious_file_is_detected(self) -> None:
        digest = sha256_file(self.file)
        client = FakeClient(
            known={
                digest: {
                    "last_analysis_stats": {"malicious": 30, "undetected": 40},
                    "last_analysis_results": {
                        "BadEngine": {"category": "malicious", "engine_name": "BadEngine", "result": "Trojan.X"},
                    },
                    "meaningful_name": "actually-malware.exe",
                }
            }
        )
        scanner = self.make_scanner(client, policy=UploadPolicy.NEVER)

        result = next(scanner.scan([self.file]))
        self.assertEqual(result.status, Status.MALICIOUS)
        self.assertTrue(result.is_threat)
        self.assertEqual(result.detection_ratio(), "30/70")
        self.assertEqual(result.detections[0].engine, "BadEngine")
        self.assertTrue(result.permalink.endswith(digest))

    def test_unknown_file_is_not_uploaded_when_policy_never(self) -> None:
        client = FakeClient()
        scanner = self.make_scanner(client, policy=UploadPolicy.NEVER)

        result = next(scanner.scan([self.file]))
        self.assertEqual(result.status, Status.UNKNOWN)
        self.assertIsNone(result.permalink)
        self.assertEqual(client.uploads, [])

    def test_unknown_file_upload_requires_confirmation(self) -> None:
        client = FakeClient(analysis={"status": "completed", "stats": {"malicious": 2, "undetected": 70}, "results": {}})
        asked: list[tuple] = []

        def confirm(path, size, sha256):
            asked.append((path, size, sha256))
            return Decision.UPLOAD

        scanner = self.make_scanner(client, policy=UploadPolicy.ASK, confirm_upload=confirm)
        result = next(scanner.scan([self.file]))

        self.assertEqual(len(asked), 1)
        self.assertEqual(client.uploads, [str(self.file)])
        self.assertTrue(result.uploaded)
        self.assertEqual(result.status, Status.MALICIOUS)

    def test_unknown_file_skipped_when_declined(self) -> None:
        client = FakeClient()
        scanner = self.make_scanner(
            client, policy=UploadPolicy.ASK, confirm_upload=lambda *_: Decision.SKIP
        )

        result = next(scanner.scan([self.file]))
        self.assertEqual(result.status, Status.UNKNOWN)
        self.assertEqual(client.uploads, [])

    def test_upload_all_is_sticky(self) -> None:
        second = self.tmp / "second.bin"
        second.write_bytes(b"another sample")
        client = FakeClient()
        calls: list[int] = []

        def confirm(*_):
            calls.append(1)
            return Decision.UPLOAD_ALL

        scanner = self.make_scanner(client, policy=UploadPolicy.ASK, confirm_upload=confirm)
        results = list(scanner.scan([self.tmp]))

        self.assertEqual(len(calls), 1)          # asked only once
        self.assertEqual(len(client.uploads), 2)
        self.assertTrue(all(result.uploaded for result in results))

    def test_policy_always_uploads_without_prompt(self) -> None:
        client = FakeClient()
        scanner = self.make_scanner(client, policy=UploadPolicy.ALWAYS)

        result = next(scanner.scan([self.file]))
        self.assertTrue(result.uploaded)
        self.assertEqual(result.status, Status.CLEAN)  # analysis reported no detections

    def test_oversized_file_is_not_offered_for_upload(self) -> None:
        client = FakeClient()
        asked: list[int] = []
        scanner = self.make_scanner(
            client,
            policy=UploadPolicy.ASK,
            max_upload_mb=0.000001,
            confirm_upload=lambda *_: asked.append(1) or Decision.UPLOAD,
        )

        result = next(scanner.scan([self.file]))
        self.assertEqual(result.status, Status.TOO_BIG)
        self.assertEqual(asked, [])
        self.assertEqual(client.uploads, [])

    def test_failed_upload_does_not_abort_the_scan(self) -> None:
        second = self.tmp / "second.bin"
        second.write_bytes(b"another sample")

        class FailingClient(FakeClient):
            def upload_file(self, path, cancel=None, on_progress=None):
                raise UploadError("uploading files larger than 32 MB requires a premium key")

        client = FailingClient()
        scanner = self.make_scanner(client, policy=UploadPolicy.ALWAYS)
        results = list(scanner.scan([self.tmp]))

        self.assertEqual([result.status for result in results], [Status.ERROR, Status.ERROR])
        self.assertTrue(all("premium" in (result.message or "") for result in results))

    def test_default_upload_limit_is_32_mb(self) -> None:
        scanner = self.make_scanner(FakeClient(), policy=UploadPolicy.NEVER)
        self.assertEqual(scanner.max_upload_bytes, 32 * 1024 * 1024)

    def test_missing_path_raises(self) -> None:
        client = FakeClient()
        scanner = self.make_scanner(client, policy=UploadPolicy.NEVER)
        with self.assertRaises(Exception):
            list(scanner.scan([self.tmp / "nope"]))


class CollectFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="filewarden-collect-"))
        self.addCleanup(self._cleanup)
        (self.tmp / "sub").mkdir()
        (self.tmp / "a.txt").write_text("a")
        (self.tmp / "sub" / "b.log").write_text("b")
        (self.tmp / "sub" / "c.txt").write_text("c")

    def _cleanup(self) -> None:
        for path in sorted(self.tmp.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink()
            else:
                path.rmdir()
        self.tmp.rmdir()

    def test_recurses_and_sorts(self) -> None:
        files = collect_files([self.tmp])
        names = [path.name for path in files]
        self.assertEqual(names, ["a.txt", "b.log", "c.txt"])

    def test_excludes_patterns(self) -> None:
        files = collect_files([self.tmp], excludes=["*.txt"])
        self.assertEqual([path.name for path in files], ["b.log"])

    def test_duplicate_paths_are_deduplicated(self) -> None:
        files = collect_files([self.tmp, self.tmp / "a.txt"])
        self.assertEqual(len(files), 3)

    def test_symlinks_are_skipped_by_default(self) -> None:
        link = self.tmp / "link.txt"
        try:
            os.symlink(self.tmp / "a.txt", link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not supported here")
        files = collect_files([self.tmp])
        self.assertNotIn(link.name, [path.name for path in files])
        files = collect_files([self.tmp], follow_symlinks=True)
        self.assertIn(link.name, [path.name for path in files])


if __name__ == "__main__":
    unittest.main()

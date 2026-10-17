"""Tests for report rendering and serialization."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from fwl.report import (
    Palette,
    format_result_line,
    format_size,
    format_summary,
    summarize,
    write_csv_report,
    write_json_report,
)
from fwl.scanner import Detection, ScanResult, Status, result_from_attributes


def make_result(path="file.bin", status=Status.CLEAN, **kwargs) -> ScanResult:
    defaults = dict(path=path, size=1024, sha256="a" * 64, status=status)
    defaults.update(kwargs)
    return ScanResult(**defaults)


class ResultParsingTests(unittest.TestCase):
    def test_malicious_attributes(self) -> None:
        attributes = {
            "last_analysis_stats": {"malicious": 5, "undetected": 60},
            "last_analysis_results": {
                "A": {"category": "malicious", "engine_name": "A", "result": "Trojan"},
                "B": {"category": "harmless", "engine_name": "B", "result": None},
                "C": {"category": "suspicious", "engine_name": "C", "result": "Riskware"},
            },
        }
        result = result_from_attributes(Path("x.bin"), 10, "f" * 64, attributes, uploaded=False)
        self.assertEqual(result.status, Status.MALICIOUS)
        self.assertEqual([d.engine for d in result.detections], ["A", "C"])

    def test_analysis_attributes(self) -> None:
        attributes = {"stats": {"undetected": 70}, "results": {}}
        result = result_from_attributes(Path("x.bin"), 10, "e" * 64, attributes, uploaded=True)
        self.assertEqual(result.status, Status.CLEAN)
        self.assertTrue(result.uploaded)


class RenderingTests(unittest.TestCase):
    def test_format_size(self) -> None:
        self.assertEqual(format_size(0), "0 B")
        self.assertEqual(format_size(2048), "2.0 KB")
        self.assertEqual(format_size(5 * 1024 * 1024), "5.0 MB")

    def test_summarize_counts(self) -> None:
        results = [
            make_result(status=Status.CLEAN),
            make_result(status=Status.MALICIOUS, stats={"malicious": 3, "undetected": 60}),
            make_result(status=Status.UNKNOWN),
            make_result(status=Status.ERROR),
        ]
        totals = summarize(results)
        self.assertEqual(totals["files"], 4)
        self.assertEqual(totals["clean"], 1)
        self.assertEqual(totals["malicious"], 1)
        self.assertEqual(totals["unknown"], 1)
        self.assertEqual(totals["errors"], 1)

    def test_line_rendering_has_no_ansi_when_disabled(self) -> None:
        palette = Palette(enabled=False)
        line = format_result_line(
            1, 10, make_result(status=Status.MALICIOUS, stats={"malicious": 1, "undetected": 9}),
            palette=palette,
        )
        self.assertNotIn("\x1b[", line)
        self.assertIn("MALICIOUS", line)

    def test_summary_lists_threats(self) -> None:
        palette = Palette(enabled=False)
        results = [
            make_result(status=Status.CLEAN),
            make_result(
                path="bad.exe", status=Status.MALICIOUS,
                stats={"malicious": 40, "undetected": 30},
                detections=[Detection(engine="E", category="malicious", verdict="Trojan")],
                permalink="https://example.test/x",
            ),
        ]
        summary = format_summary(results, 12.5, palette)
        self.assertIn("Threats found", summary)
        self.assertIn("bad.exe", summary)


class SerializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.results = [
            make_result(status=Status.CLEAN),
            make_result(
                path="bad.exe", status=Status.SUSPICIOUS,
                stats={"malicious": 0, "suspicious": 2, "undetected": 60},
                detections=[Detection(engine="E", category="suspicious", verdict="Riskware")],
                permalink="https://example.test/x", message="uploaded to VirusTotal", uploaded=True,
            ),
        ]

    def test_json_report_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.json"
            write_json_report(self.results, target, meta={"paths": ["/tmp/demo"]})
            data = json.loads(target.read_text(encoding="utf-8"))

        self.assertEqual(data["tool"], "filewarden")
        self.assertEqual(data["summary"]["files"], 2)
        self.assertEqual(data["summary"]["uploaded"], 1)
        self.assertEqual(data["results"][1]["status"], "suspicious")
        self.assertEqual(data["results"][1]["detections_count"], 2)
        self.assertEqual(data["meta"]["paths"], ["/tmp/demo"])

    def test_csv_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.csv"
            write_csv_report(self.results, target)
            with open(target, encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["status"], "suspicious")
        self.assertEqual(rows[1]["uploaded"], "yes")


if __name__ == "__main__":
    unittest.main()

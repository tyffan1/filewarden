"""Rendering of scan results: terminal output and JSON/CSV reports."""

from __future__ import annotations

import csv
import datetime as _dt
import json
import os
from dataclasses import asdict
from typing import IO, Any, Iterable, Sequence

from . import __version__
from .scanner import STATUS_ORDER, ScanResult, Status

STATUS_LABELS = {
    Status.MALICIOUS: "MALICIOUS",
    Status.SUSPICIOUS: "suspicious",
    Status.CLEAN: "clean",
    Status.UNKNOWN: "not in VT",
    Status.TOO_BIG: "oversized",
    Status.ERROR: "error",
}

STATUS_SYMBOLS = {
    Status.MALICIOUS: "✖",
    Status.SUSPICIOUS: "⚠",
    Status.CLEAN: "✔",
    Status.UNKNOWN: "?",
    Status.TOO_BIG: "·",
    Status.ERROR: "✖",
}

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def format_size(size: int | None) -> str:
    if size is None:
        return "?"
    value = float(size)
    index = 0
    while value >= 1024 and index < len(_UNITS) - 1:
        value /= 1024
        index += 1
    if index == 0:
        return f"{int(value)} {_UNITS[index]}"
    return f"{value:.1f} {_UNITS[index]}"


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_detections(detections: Sequence, limit: int = 3) -> str:
    """Short engine summary: ``Kaspersky: Trojan.X, DrWeb: Y``."""
    parts = []
    for detection in detections[:limit]:
        if detection.verdict:
            parts.append(f"{detection.engine}: {detection.verdict}")
        else:
            parts.append(detection.engine)
    if len(detections) > limit:
        parts.append(f"and {len(detections) - limit} more")
    return ", ".join(parts)


class Palette:
    """ANSI colors, disabled automatically for pipes and ``NO_COLOR``."""

    CODES = {
        "malicious": "\x1b[1;31m",
        "suspicious": "\x1b[1;33m",
        "clean": "\x1b[32m",
        "unknown": "\x1b[36m",
        "error": "\x1b[35m",
        "dim": "\x1b[2m",
        "bold": "\x1b[1m",
        "reset": "\x1b[0m",
    }

    STATUS_COLORS = {
        Status.MALICIOUS: "malicious",
        Status.SUSPICIOUS: "suspicious",
        Status.CLEAN: "clean",
        Status.UNKNOWN: "unknown",
        Status.TOO_BIG: "unknown",
        Status.ERROR: "error",
    }

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def paint(self, text: str, color: str) -> str:
        if not self.enabled or color not in self.CODES:
            return text
        return f"{self.CODES[color]}{text}{self.CODES['reset']}"

    def verdict(self, status: Status) -> str:
        label = f"{STATUS_SYMBOLS[status]} {STATUS_LABELS[status]}"
        return self.paint(label, self.STATUS_COLORS[status])


def format_result_line(
    index: int,
    total: int,
    result: ScanResult,
    *,
    palette: Palette,
    verbose: bool = False,
) -> str:
    """One line per file, optionally followed by an indented detail line."""
    counter = f"[{index:>4}/{total}]"
    verdict = palette.verdict(result.status)
    if result.status in (Status.MALICIOUS, Status.SUSPICIOUS):
        verdict += " " + palette.paint(result.detection_ratio(), "dim")

    path = result.path
    if not verbose and len(path) > 64:
        path = "…" + path[-63:]
    parts = [counter, palette.paint(path, "dim"), format_size(result.size).rjust(8), verdict]

    if result.message and result.status in (Status.ERROR, Status.TOO_BIG, Status.UNKNOWN):
        parts.append(palette.paint(f"({result.message})", "dim"))
    elif result.detections:
        parts.append(palette.paint(format_detections(result.detections), "dim"))

    line = "  ".join(parts)
    if verbose and result.status is not Status.CLEAN:
        details = [
            f"        sha256: {result.sha256 or '-'}",
            f"        report: {result.permalink or '-'}",
        ]
        if result.detections:
            details.append("        engines: " + format_detections(result.detections, limit=10))
        line += "\n" + "\n".join(details)
    elif verbose and result.uploaded:
        line += "\n" + f"        uploaded: {result.permalink or '-'}"
    return line


def summarize(results: Iterable[ScanResult]) -> dict[str, Any]:
    results = list(results)
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status.value] = counts.get(result.status.value, 0) + 1
    return {
        "files": len(results),
        "bytes": sum(result.size for result in results),
        "clean": counts.get("clean", 0),
        "suspicious": counts.get("suspicious", 0),
        "malicious": counts.get("malicious", 0),
        "unknown": counts.get("unknown", 0),
        "too_big": counts.get("too_big", 0),
        "errors": counts.get("error", 0),
        "uploaded": sum(1 for result in results if result.uploaded),
    }


def _verdict_row(palette: Palette, status: Status, count: int) -> str:
    label = f"{STATUS_SYMBOLS[status]} {STATUS_LABELS[status]}".ljust(26)
    return f"  {palette.paint(label, palette.STATUS_COLORS[status])} {count}"


def format_summary(results: Sequence[ScanResult], elapsed: float, palette: Palette) -> str:
    totals = summarize(results)
    lines = [
        "",
        palette.paint("── Summary " + "─" * 49, "bold"),
        f"Files scanned: {totals['files']} ({format_size(totals['bytes'])})",
        _verdict_row(palette, Status.CLEAN, totals["clean"]),
        _verdict_row(palette, Status.SUSPICIOUS, totals["suspicious"]),
        _verdict_row(palette, Status.MALICIOUS, totals["malicious"]),
        _verdict_row(palette, Status.UNKNOWN, totals["unknown"]),
        _verdict_row(palette, Status.TOO_BIG, totals["too_big"]),
        _verdict_row(palette, Status.ERROR, totals["errors"]),
        f"Uploaded to VirusTotal: {totals['uploaded']}",
        f"Time: {format_duration(elapsed)}",
    ]
    threats = sorted(
        (r for r in results if r.is_threat), key=lambda r: (STATUS_ORDER[r.status], -r.detections_count)
    )
    if threats:
        lines.append("")
        lines.append(palette.paint("Threats found:", "malicious"))
        for number, result in enumerate(threats, start=1):
            lines.append(
                f"  {number}. {result.path}  {result.detection_ratio()}  "
                f"{palette.paint(result.permalink or '', 'dim')}"
            )
            if result.detections:
                lines.append(f"     {format_detections(result.detections, limit=5)}")
    return "\n".join(lines)


def _result_to_dict(result: ScanResult) -> dict[str, Any]:
    data = asdict(result)
    data["status"] = result.status.value
    data["detections_count"] = result.detections_count
    data["engines_total"] = result.engines_total
    return data


def build_report(results: Sequence[ScanResult], meta: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "tool": "filewarden",
        "version": __version__,
        "generated_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "meta": meta or {},
        "summary": summarize(results),
        "results": [_result_to_dict(result) for result in results],
    }


def open_text_target(target: str | os.PathLike[str] | IO[str]) -> tuple[IO[str], bool]:
    if hasattr(target, "write"):
        return target, False  # type: ignore[return-value]
    return open(target, "w", encoding="utf-8", newline=""), True


def write_json_report(
    results: Sequence[ScanResult],
    target: str | os.PathLike[str] | IO[str],
    meta: dict[str, Any] | None = None,
) -> None:
    stream, should_close = open_text_target(target)
    try:
        json.dump(build_report(results, meta), stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    finally:
        if should_close:
            stream.close()


def write_csv_report(
    results: Sequence[ScanResult],
    target: str | os.PathLike[str],
) -> None:
    # utf-8-sig keeps Excel (Windows) happy with non-ASCII paths.
    with open(target, "w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "path", "size_bytes", "sha256", "status", "detections", "engines_total",
                "uploaded", "permalink", "message", "detected_engines",
            ]
        )
        for result in results:
            writer.writerow(
                [
                    result.path,
                    result.size,
                    result.sha256,
                    result.status.value,
                    result.detections_count,
                    result.engines_total,
                    "yes" if result.uploaded else "no",
                    result.permalink or "",
                    result.message or "",
                    format_detections(result.detections, limit=5),
                ]
            )

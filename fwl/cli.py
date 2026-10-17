"""Command line interface: ``filewarden.py <file|folder> [...]``."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import threading
import time
from pathlib import Path
from typing import Sequence

from . import __version__, config
from .client import VirusTotalClient
from .errors import ApiKeyError, CancelledError, FileWardenError, QuotaExceededError
from .report import (
    Palette,
    format_result_line,
    format_size,
    format_summary,
    write_csv_report,
    write_json_report,
)
from .scanner import (
    Decision,
    Scanner,
    Status,
    UploadPolicy,
    collect_files,
)

KEY_HELP = (
    "The key can be provided in one of the following ways:\n"
    "  1) filewarden --set-key <KEY>        (saved to the settings file)\n"
    "  2) export VIRUSTOTAL_API_KEY=<KEY>   (environment variable)\n"
    "  3) filewarden -k <KEY> ...           (current run only)\n"
    "Free key: https://www.virustotal.com/gui/my-apikey"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filewarden",
        description=(
            "Scan files and folders with VirusTotal. Every file is looked up by its "
            "SHA-256 first; uploads happen only with your explicit confirmation."
        ),
        epilog=KEY_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", help="files and/or folders to scan")
    parser.add_argument("-k", "--api-key", help="VirusTotal API key")
    parser.add_argument(
        "--set-key", metavar="KEY", help="save the API key to the settings file and exit"
    )
    parser.add_argument(
        "--rpm", type=float,
        help="API request rate limit per minute (public API: 4; premium keys allow more)",
    )
    parser.add_argument(
        "--upload", choices=[policy.value for policy in UploadPolicy],
        help="upload policy for unknown files: ask (default), never, always",
    )
    parser.add_argument(
        "--max-upload-mb", type=float, dest="max_upload_mb", metavar="MB",
        help="maximum file size to upload, MB (default 32)",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="skip files matching the pattern (repeatable)",
    )
    parser.add_argument(
        "--follow-symlinks", action="store_true",
        help="follow symbolic links (skipped by default)",
    )
    parser.add_argument("--json", metavar="FILE", help="save the report as JSON")
    parser.add_argument("--csv", metavar="FILE", help="save the report as CSV")
    parser.add_argument(
        "--analysis-timeout", type=float, default=900.0, metavar="SEC",
        help="how many seconds to wait for the analysis after an upload (default 900)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="show problems only")
    parser.add_argument("--no-color", action="store_true", help="disable colors")
    parser.add_argument("--version", action="version", version=f"filewarden {__version__}")
    return parser


class UploadPrompter:
    """Terminal confirmation for uploading an unknown file."""

    def __init__(self, interactive: bool, palette: Palette):
        self.interactive = interactive
        self.palette = palette

    def __call__(self, path: Path, size: int, sha256: str) -> Decision:
        if not self.interactive:
            return Decision.SKIP
        print()
        print(self.palette.paint(f"File not found on VirusTotal: {path}", "bold"))
        print(f"  size: {format_size(size)}")
        print(f"  sha256: {sha256}")
        print(
            "  Note: once uploaded, the file becomes available to researchers and "
            "vendors on VirusTotal. Do not upload personal or confidential documents."
        )
        while True:
            try:
                answer = input(
                    "  Upload this file? [y] yes / [n] no / [a] yes to all / [q] no to all: "
                )
            except EOFError:
                return Decision.SKIP
            answer = answer.strip().lower()
            if answer in ("y", "yes"):
                return Decision.UPLOAD
            if answer in ("n", "no", ""):
                return Decision.SKIP
            if answer in ("a", "all"):
                return Decision.UPLOAD_ALL
            if answer in ("q", "quit"):
                return Decision.SKIP_ALL
            print("  Please answer y, n, a or q.")


def _emit(text: str) -> None:
    print(text, flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.set_key:
        path = config.save_api_key(args.set_key)
        _emit(f"API key saved: {path}")
        if not args.paths:
            return 0

    if not args.paths:
        parser.error("provide at least one file or folder to scan")

    stored = config.load_config()
    key = config.resolve_api_key(args.api_key)
    if not key:
        if sys.stdin.isatty():
            try:
                key = getpass.getpass("VirusTotal API key: ").strip()
            except (EOFError, KeyboardInterrupt):
                key = ""
        if not key:
            _emit("Error: no API key configured.\n" + KEY_HELP)
            return 2

    palette = Palette(
        enabled=(
            not args.no_color
            and not os.environ.get("NO_COLOR")
            and sys.stdout.isatty()
        )
    )
    rpm = args.rpm if args.rpm is not None else float(stored.get("rpm") or 4.0)
    max_upload_mb = (
        args.max_upload_mb
        if args.max_upload_mb is not None
        else float(stored.get("max_upload_mb") or 32.0)
    )
    policy = UploadPolicy(args.upload or str(stored.get("upload_policy") or "ask"))

    def client_log(message: str) -> None:
        if args.verbose:
            _emit(palette.paint(f"    · {message}", "dim"))

    client = VirusTotalClient(key, rpm=max(0.0, rpm), log=client_log)

    try:
        client.verify_key()
    except ApiKeyError as exc:
        _emit(f"Error: {exc}")
        _emit("Check your key at https://www.virustotal.com/gui/my-apikey")
        return 2
    except FileWardenError as exc:
        _emit(f"Could not reach VirusTotal: {exc}")
        return 2

    interactive = policy is UploadPolicy.ASK and sys.stdin.isatty()
    if policy is UploadPolicy.ASK and not interactive:
        _emit(
            "Note: interactive input is unavailable, so unknown files will not be "
            "uploaded (use --upload always to allow uploads)."
        )
    prompter = UploadPrompter(interactive, palette)

    try:
        files = collect_files(
            args.paths, follow_symlinks=args.follow_symlinks, excludes=args.exclude
        )
    except FileWardenError as exc:
        _emit(f"Error: {exc}")
        return 2

    if not files:
        _emit("No files to scan in the given paths.")
        return 0

    total_bytes = sum(path.stat().st_size for path in files if path.is_file())
    _emit(
        f"Files to scan: {len(files)} ({format_size(total_bytes)})"
    )
    if rpm > 0:
        estimate = len(files) / rpm
        _emit(
            palette.paint(
                f"Hash lookups alone will take at least {estimate:.0f} min "
                f"at {rpm:g} requests/min.",
                "dim",
            )
        )
    if len(files) > 500:
        _emit(
            palette.paint(
                "Heads-up: a free key allows 500 requests per day — "
                "large folders may need a premium key.",
                "dim",
            )
        )

    scanner = Scanner(
        client,
        policy=policy,
        max_upload_mb=max_upload_mb,
        confirm_upload=prompter,
        cancel=threading.Event(),
        on_note=lambda text: _emit(palette.paint(f"    → {text}", "dim")),
        analysis_timeout=args.analysis_timeout,
    )

    results = []
    started = time.monotonic()
    interrupted = False
    try:
        for index, result in enumerate(
            scanner.scan(files, follow_symlinks=args.follow_symlinks, excludes=args.exclude),
            start=1,
        ):
            results.append(result)
            if args.quiet and not (
                result.is_threat or result.status in (Status.ERROR, Status.TOO_BIG, Status.UNKNOWN)
            ):
                continue
            _emit(format_result_line(index, len(files), result, palette=palette, verbose=args.verbose))
    except KeyboardInterrupt:
        interrupted = True
        _emit("\nInterrupted by the user (Ctrl+C).")
    except CancelledError:
        interrupted = True
        _emit("\nScan cancelled.")
    except ApiKeyError as exc:
        _emit(f"\nError: {exc}")
        return 2
    except QuotaExceededError as exc:
        _emit(f"\n{exc}")
        return 2
    except FileWardenError as exc:
        _emit(f"\nError: {exc}")
        return 2

    elapsed = time.monotonic() - started
    if results:
        _emit(format_summary(results, elapsed, palette))

    meta = {
        "paths": [str(path) for path in args.paths],
        "upload_policy": policy.value,
        "rpm": rpm,
        "max_upload_mb": max_upload_mb,
    }
    for target, writer in ((args.json, write_json_report), (args.csv, write_csv_report)):
        if not target:
            continue
        try:
            if writer is write_json_report:
                writer(results, target, meta)
            else:
                writer(results, target)
            _emit(f"Report saved: {target}")
        except OSError as exc:
            _emit(f"Could not save the report {target}: {exc}")
            return 2

    if interrupted:
        return 130
    if any(result.is_threat for result in results):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

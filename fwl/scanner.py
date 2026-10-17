"""Hash-first scanning logic.

Policy: a file is *always* looked up by its SHA-256 first.  It is uploaded
to VirusTotal only when the hash is unknown **and** the user explicitly
agreed to the upload.  Files uploaded to VirusTotal become available to
researchers and vendors, so personal documents must never be uploaded
silently.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

from .client import VirusTotalClient
from .errors import (
    ApiKeyError,
    CancelledError,
    FileWardenError,
    QuotaExceededError,
    UnknownHashError,
)
from .ratelimit import CancelToken

HASH_CHUNK = 1024 * 1024
DEFAULT_MAX_UPLOAD_MB = 32.0


class UploadPolicy(str, Enum):
    """What to do when a hash is unknown."""

    NEVER = "never"      # hash lookup only, never upload
    ASK = "ask"          # ask the user for every unknown file (default)
    ALWAYS = "always"    # upload without asking (explicit opt-in)


class Decision(str, Enum):
    """Answer of the confirmation callback."""

    UPLOAD = "upload"
    SKIP = "skip"
    UPLOAD_ALL = "upload_all"
    SKIP_ALL = "skip_all"


class Status(str, Enum):
    """Final verdict of a single file."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"       # not in VirusTotal, upload not performed
    TOO_BIG = "too_big"       # not in VirusTotal and above the upload limit
    ERROR = "error"


#: Used to sort reports: threats first, clean files last.
STATUS_ORDER = {
    Status.MALICIOUS: 0,
    Status.SUSPICIOUS: 1,
    Status.ERROR: 2,
    Status.TOO_BIG: 3,
    Status.UNKNOWN: 4,
    Status.CLEAN: 5,
}

#: Statuses that make the process exit with code 1.
THREAT_STATUSES = (Status.MALICIOUS, Status.SUSPICIOUS)


@dataclass(slots=True)
class Detection:
    """One engine that flagged the file."""

    engine: str
    category: str          # "malicious" | "suspicious"
    verdict: str | None    # engine-specific threat name


@dataclass(slots=True)
class ScanResult:
    """Everything FileWarden knows about a single file."""

    path: str
    size: int
    sha256: str
    status: Status
    stats: dict[str, int] = field(default_factory=dict)
    detections: list[Detection] = field(default_factory=list)
    uploaded: bool = False
    permalink: str | None = None
    message: str | None = None
    type_description: str | None = None
    names: str | None = None
    times_submitted: int | None = None
    reputation: int | None = None

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def engines_total(self) -> int:
        return sum(int(v) for v in self.stats.values())

    @property
    def malicious_count(self) -> int:
        return int(self.stats.get("malicious", 0))

    @property
    def suspicious_count(self) -> int:
        return int(self.stats.get("suspicious", 0))

    @property
    def detections_count(self) -> int:
        return self.malicious_count + self.suspicious_count

    @property
    def is_threat(self) -> bool:
        return self.status in THREAT_STATUSES

    def detection_ratio(self) -> str:
        if not self.engines_total:
            return "-"
        return f"{self.detections_count}/{self.engines_total}"


class _NeverCancel:
    def is_set(self) -> bool:
        return False


NEVER_CANCEL = _NeverCancel()


def sha256_file(path: str | os.PathLike[str], cancel: CancelToken | None = None) -> str:
    """Stream a file through SHA-256 without holding it in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            if cancel is not None and cancel.is_set():
                raise CancelledError("operation cancelled")
            chunk = handle.read(HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _is_excluded(path: Path, patterns: Sequence[str]) -> bool:
    if not patterns:
        return False
    name = path.name
    full = path.as_posix()
    return any(
        fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(full, pattern)
        for pattern in patterns
    )


def collect_files(
    paths: Iterable[str | os.PathLike[str]],
    *,
    follow_symlinks: bool = False,
    excludes: Sequence[str] = (),
) -> list[Path]:
    """Expand files/folders into a sorted, de-duplicated list of files.

    Symlinks are skipped unless ``follow_symlinks`` is set, so a folder
    never pulls in half of the file system through a stray link.  Files are
    de-duplicated by absolute path (two links to the same inode stay
    distinct, which is what the user sees in the report), and cyclic
    symlinks cannot cause an endless walk.
    """
    collected: list[Path] = []
    seen: set[str] = set()
    visited_dirs: set[str] = set()

    def add(candidate: Path) -> None:
        if candidate.is_symlink() and not follow_symlinks:
            return
        if not candidate.is_file():
            return  # fifo, socket, device, dangling symlink
        if _is_excluded(candidate, excludes):
            return
        key = os.path.normcase(os.path.abspath(candidate))
        if key in seen:
            return
        seen.add(key)
        collected.append(candidate)

    for raw in paths:
        root = Path(raw).expanduser()
        if root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
                real_dir = os.path.realpath(dirpath)
                if real_dir in visited_dirs:
                    dirnames[:] = []
                    continue
                visited_dirs.add(real_dir)
                dirnames[:] = sorted(
                    d for d in dirnames if not _is_excluded(Path(dirpath) / d, excludes)
                )
                for filename in sorted(filenames):
                    add(Path(dirpath) / filename)
        elif root.is_file() or root.is_symlink():
            add(root)
        else:
            raise FileWardenError(f"path not found or not a file/folder: {root}")

    collected.sort(key=lambda item: str(item).lower())
    return collected


def _classify(stats: dict[str, int]) -> Status:
    if int(stats.get("malicious", 0)):
        return Status.MALICIOUS
    if int(stats.get("suspicious", 0)):
        return Status.SUSPICIOUS
    return Status.CLEAN


def _detections_from(results: dict[str, Any]) -> list[Detection]:
    detections: list[Detection] = []
    for engine, info in (results or {}).items():
        if not isinstance(info, dict):
            continue
        category = str(info.get("category") or "")
        if category not in ("malicious", "suspicious"):
            continue
        detections.append(
            Detection(
                engine=str(info.get("engine_name") or engine),
                category=category,
                verdict=(info.get("result") or None),
            )
        )
    detections.sort(key=lambda d: (0 if d.category == "malicious" else 1, d.engine.lower()))
    return detections


def result_from_attributes(
    path: Path,
    size: int,
    sha256: str,
    attributes: dict[str, Any],
    *,
    uploaded: bool,
) -> ScanResult:
    """Turn a file/analysis payload into a :class:`ScanResult`."""
    stats_raw = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    stats = {str(k): int(v) for k, v in stats_raw.items() if isinstance(v, (int, float))}
    results = attributes.get("last_analysis_results") or attributes.get("results") or {}
    status = _classify(stats)
    message: str | None = None
    if uploaded and not _detections_from(results):
        message = "uploaded to VirusTotal: no malicious detections"
    elif uploaded:
        message = "uploaded to VirusTotal"
    return ScanResult(
        path=str(path),
        size=size,
        sha256=sha256,
        status=status,
        stats=stats,
        detections=_detections_from(results),
        uploaded=uploaded,
        permalink=VirusTotalClient.report_url(sha256),
        message=message,
        type_description=attributes.get("type_description"),
        names=attributes.get("meaningful_name") or attributes.get("name"),
        times_submitted=attributes.get("times_submitted"),
        reputation=attributes.get("reputation"),
    )


ConfirmUpload = Callable[[Path, int, str], Decision]


class Scanner:
    """Walks files, asks VirusTotal about their hashes and reports results."""

    def __init__(
        self,
        client: VirusTotalClient,
        *,
        policy: UploadPolicy = UploadPolicy.ASK,
        max_upload_mb: float = DEFAULT_MAX_UPLOAD_MB,
        confirm_upload: ConfirmUpload | None = None,
        cancel: CancelToken | None = None,
        on_status: Callable[[str], None] | None = None,
        on_note: Callable[[str], None] | None = None,
        on_progress: Callable[[int, int, Path | None], None] | None = None,
        analysis_timeout: float = 900.0,
        analysis_poll_interval: float = 15.0,
    ):
        self.client = client
        self.policy = policy
        self.max_upload_bytes = max(0, int(max_upload_mb * 1024 * 1024))
        self.confirm_upload = confirm_upload
        self.cancel = cancel or NEVER_CANCEL
        self.on_status = on_status or (lambda _text: None)
        self.on_note = on_note or (lambda _text: None)
        self.on_progress = on_progress or (lambda _done, _total, _path: None)
        self.analysis_timeout = analysis_timeout
        self.analysis_poll_interval = analysis_poll_interval
        self._sticky: Decision | None = None

    # ---------------------------------------------------------------- helpers

    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise CancelledError("scan cancelled")

    # ------------------------------------------------------------------ scan

    def scan(
        self,
        paths: Iterable[str | os.PathLike[str]],
        *,
        follow_symlinks: bool = False,
        excludes: Sequence[str] = (),
    ) -> Iterator[ScanResult]:
        """Yield one :class:`ScanResult` per file, in stable order."""
        files = collect_files(paths, follow_symlinks=follow_symlinks, excludes=excludes)
        total = len(files)
        self.on_progress(0, total, None)
        for index, path in enumerate(files, start=1):
            self._check_cancel()
            self.on_status(f"[{index}/{total}] {path}")
            result = self._scan_file(path)
            self.on_progress(index, total, path)
            yield result

    def _scan_file(self, path: Path) -> ScanResult:
        try:
            size = path.stat().st_size
        except OSError as exc:
            return ScanResult(
                path=str(path), size=0, sha256="", status=Status.ERROR,
                message=f"could not read file information: {exc}",
            )
        try:
            digest = sha256_file(path, cancel=self.cancel)
        except CancelledError:
            raise
        except OSError as exc:
            return ScanResult(
                path=str(path), size=size, sha256="", status=Status.ERROR,
                message=f"could not read the file: {exc}",
            )

        try:
            attributes = self.client.get_file_report(digest, cancel=self.cancel)
        except UnknownHashError:
            return self._handle_unknown(path, size, digest)
        except (CancelledError, ApiKeyError, QuotaExceededError):
            raise
        except FileWardenError as exc:
            return ScanResult(
                path=str(path), size=size, sha256=digest, status=Status.ERROR,
                message=str(exc),
            )
        return result_from_attributes(path, size, digest, attributes, uploaded=False)

    def _handle_unknown(self, path: Path, size: int, digest: str) -> ScanResult:
        """The hash is not on VirusTotal: decide about a possible upload."""

        def unknown(message: str, status: Status = Status.UNKNOWN) -> ScanResult:
            return ScanResult(
                path=str(path), size=size, sha256=digest, status=status,
                message=message, permalink=None,
            )

        if self.policy is UploadPolicy.NEVER:
            return unknown("not on VirusTotal; uploads are disabled")

        if size > self.max_upload_bytes:
            limit_mb = self.max_upload_bytes / (1024 * 1024)
            return unknown(
                f"not on VirusTotal; size {size / (1024 * 1024):.3g} MB exceeds "
                f"the {limit_mb:.3g} MB upload limit",
                Status.TOO_BIG,
            )

        decision: Decision
        if self._sticky is not None:
            decision = self._sticky
        elif self.policy is UploadPolicy.ALWAYS:
            decision = Decision.UPLOAD
        elif self.confirm_upload is None:
            decision = Decision.SKIP
        else:
            decision = self.confirm_upload(path, size, digest)
            if decision is Decision.UPLOAD_ALL:
                self._sticky = Decision.UPLOAD
            elif decision is Decision.SKIP_ALL:
                self._sticky = Decision.SKIP

        if decision in (Decision.SKIP, Decision.SKIP_ALL):
            return unknown("not on VirusTotal; upload declined by the user")

        self.on_note(f"uploading to VirusTotal: {path.name}")
        try:
            analysis_id = self.client.upload_file(path, cancel=self.cancel)
            attributes = self.client.wait_for_analysis(
                analysis_id,
                cancel=self.cancel,
                on_status=self.on_note,
                timeout=self.analysis_timeout,
                poll_interval=self.analysis_poll_interval,
            )
        except (CancelledError, ApiKeyError, QuotaExceededError):
            raise
        except FileWardenError as exc:
            return ScanResult(
                path=str(path), size=size, sha256=digest, status=Status.ERROR,
                message=f"upload failed: {exc}",
            )
        return result_from_attributes(path, size, digest, attributes, uploaded=True)

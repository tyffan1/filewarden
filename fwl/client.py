"""Minimal VirusTotal API v3 client built on the Python standard library.

Only what the scanner needs:

* ``GET  /files/{sha256}``    — look a file up by hash (no upload ever happens);
* ``POST /files``             — upload a file (only after explicit user consent);
* ``GET  /analyses/{id}``     — poll the analysis started by an upload;
* ``GET  /files/upload_url``  — premium helper for files above the direct limit.

The transport is injectable, which keeps the unit tests offline.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from typing import Callable, Mapping

from .errors import (
    AnalysisTimeout,
    ApiError,
    ApiKeyError,
    CancelledError,
    NetworkError,
    NotFoundError,
    QuotaExceededError,
    UnknownHashError,
    UploadError,
)
from .ratelimit import CancelToken, RateLimiter

API_BASE = "https://www.virustotal.com/api/v3"
GUI_BASE = "https://www.virustotal.com/gui/file"

DEFAULT_TIMEOUT = 90.0
#: VirusTotal knows the empty file, so its hash doubles as a cheap key check.
EMPTY_FILE_SHA256 = hashlib.sha256(b"").hexdigest()

Transport = Callable[[str, str, bytes | None, Mapping[str, str], float], tuple[int, dict, dict]]
ErrorLogger = Callable[[str], None]


def _decode_json(raw: bytes) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _stdlib_transport(
    method: str, url: str, body: bytes | None, headers: Mapping[str, str], timeout: float
) -> tuple[int, dict, dict]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, _decode_json(response.read()), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, _decode_json(exc.read()), dict(exc.headers)
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
        raise NetworkError(f"network error: {exc}") from exc


def _error_info(payload: dict, status: int) -> tuple[str, str]:
    error = payload.get("error") or {}
    code = str(error.get("code") or "")
    message = str(error.get("message") or f"HTTP {status}")
    return code, message


def _retry_after(headers: Mapping[str, str]) -> float:
    for name in ("Retry-After", "X-RateLimit-Reset"):
        raw = headers.get(name) or headers.get(name.lower())
        if not raw:
            continue
        try:
            value = float(raw)
        except ValueError:
            continue
        # X-RateLimit-Reset may be an absolute epoch timestamp.
        if value > 1_000_000_000:
            value = value - time.time()
        if value > 0:
            return value
    return 0.0


def encode_multipart(filename: str, data: bytes) -> tuple[str, bytes]:
    """Build a multipart/form-data body for the ``files`` endpoint."""
    boundary = uuid.uuid4().hex
    safe_name = (
        filename.encode("utf-8", "replace")
        .decode("utf-8")
        .replace('"', "_")
        .replace("\r", "")
        .replace("\n", "")
    )
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("ascii")
    return boundary, head + data + tail


class VirusTotalClient:
    """Thin, well-behaved wrapper around the public VirusTotal API."""

    def __init__(
        self,
        api_key: str,
        *,
        rpm: float = 4.0,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = 4,
        upload_retries: int = 2,
        backoff: float = 5.0,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        log: ErrorLogger | None = None,
    ):
        key = (api_key or "").strip()
        if not key:
            raise ApiKeyError("VirusTotal API key is not set")
        self.api_key = key
        self.timeout = timeout
        self.max_retries = max_retries
        self.upload_retries = upload_retries
        self.backoff = backoff
        self._clock = clock
        self._sleep = sleep
        self._transport = transport or _stdlib_transport
        self._log = log or (lambda _message: None)
        self.user_agent = "filewarden/0.1 (VirusTotal hash-first scanner)"
        self.limiter = RateLimiter(rpm, clock=clock, sleep=sleep)

    # ------------------------------------------------------------------ http

    def _sleep_cancellable(self, seconds: float, cancel: CancelToken | None) -> None:
        deadline = self._clock() + seconds
        while True:
            if cancel is not None and cancel.is_set():
                raise CancelledError("operation cancelled")
            remaining = deadline - self._clock()
            if remaining <= 0:
                return
            self._sleep(min(remaining, 0.2))

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        cancel: CancelToken | None = None,
        retries: int | None = None,
    ) -> dict:
        attempts = self.max_retries if retries is None else retries
        request_headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if headers:
            request_headers.update(headers)

        last_error: ApiError | None = None
        for attempt in range(attempts + 1):
            if cancel is not None and cancel.is_set():
                raise CancelledError("operation cancelled")
            self.limiter.acquire(cancel)
            try:
                status, payload, response_headers = self._transport(
                    method, url, body, request_headers, self.timeout
                )
            except NetworkError as exc:
                last_error = ApiError(str(exc))
                if attempt >= attempts:
                    raise
                self._log(f"network error: {exc}; retry {attempt + 1}/{attempts}")
                self._sleep_cancellable(self.backoff * (2**attempt), cancel)
                continue

            if 200 <= status < 300:
                return payload

            code, message = _error_info(payload, status)

            if status == 429:
                wait = max(_retry_after(response_headers), self.backoff * (2**attempt))
                self._log(f"rate limited (HTTP 429); cooling down {wait:.0f}s")
                last_error = QuotaExceededError(
                    "VirusTotal request quota is exhausted — try again later or raise "
                    "the rate limit with --rpm (premium key)",
                    status=status,
                    code=code or "QuotaExceededError",
                )
                self.limiter.penalize(wait)
                continue

            if status in (500, 502, 503, 504):
                last_error = ApiError(f"VirusTotal responded with HTTP {status}", status=status, code=code)
                if attempt >= attempts:
                    raise last_error
                self._log(f"HTTP {status}; retry {attempt + 1}/{attempts}")
                self._sleep_cancellable(self.backoff * (2**attempt), cancel)
                continue

            if status in (401, 403):
                detail = message if message and not message.startswith("HTTP ") else ""
                raise ApiKeyError(
                    "invalid or unauthorized VirusTotal API key (HTTP %d)%s"
                    % (status, f": {detail}" if detail else ""),
                    status=status,
                    code=code,
                )
            if status == 404:
                raise NotFoundError(message, status=status, code=code or "NotFoundError")
            raise ApiError(message, status=status, code=code)

        if last_error is not None:
            raise last_error
        raise ApiError("unknown error while talking to VirusTotal")

    # -------------------------------------------------------------- endpoints

    def verify_key(self, cancel: CancelToken | None = None) -> bool:
        """Cheap key check: look up the hash of the empty file."""
        try:
            self.get_file_report(EMPTY_FILE_SHA256, cancel=cancel)
        except UnknownHashError:
            pass
        return True

    def get_file_report(self, sha256: str, cancel: CancelToken | None = None) -> dict:
        """Return the ``data.attributes`` of a file report.

        Raises :class:`UnknownHashError` when VirusTotal does not know the
        hash — the caller has to decide whether an upload is acceptable.
        """
        try:
            payload = self._request("GET", f"{API_BASE}/files/{sha256}", cancel=cancel)
        except NotFoundError as exc:
            raise UnknownHashError(sha256) from exc
        return (payload.get("data") or {}).get("attributes") or {}

    def get_upload_url(self, cancel: CancelToken | None = None) -> str:
        """Ask for the special upload endpoint (premium keys, >32 MB files)."""
        try:
            payload = self._request("GET", f"{API_BASE}/files/upload_url", cancel=cancel)
        except ApiKeyError as exc:
            raise UploadError(
                "uploading files larger than 32 MB requires a premium VirusTotal key "
                "(the /files/upload_url endpoint refused the request)"
            ) from exc
        url = payload.get("data")
        if not isinstance(url, str) or not url.startswith("http"):
            raise UploadError("VirusTotal did not return an upload URL for large files")
        return url

    def upload_file(
        self,
        path: str | os.PathLike[str],
        *,
        cancel: CancelToken | None = None,
        on_progress: Callable[[int, int], None] | None = None,
        direct_limit: int | None = None,
    ) -> str:
        """Upload a file and return the analysis id.

        ``direct_limit`` is the size in bytes above which the premium
        ``upload_url`` endpoint has to be used (defaults to 32 MB).
        """
        path = os.fspath(path)
        size = os.path.getsize(path)
        limit = 32 * 1024 * 1024 if direct_limit is None else direct_limit

        buffer = bytearray()
        with open(path, "rb") as handle:
            while True:
                if cancel is not None and cancel.is_set():
                    raise CancelledError("operation cancelled")
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                buffer += chunk
                if on_progress is not None:
                    on_progress(len(buffer), size)

        boundary, body = encode_multipart(os.path.basename(path), bytes(buffer))
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }
        url = f"{API_BASE}/files"
        if size > limit:
            url = self.get_upload_url(cancel=cancel)

        payload = self._request(
            "POST", url, body=body, headers=headers, cancel=cancel, retries=self.upload_retries
        )
        analysis_id = (payload.get("data") or {}).get("id")
        if not isinstance(analysis_id, str) or not analysis_id:
            raise UploadError("VirusTotal did not return an analysis id after the upload")
        return analysis_id

    def get_analysis(self, analysis_id: str, cancel: CancelToken | None = None) -> dict:
        """Return the ``data.attributes`` of an analysis."""
        payload = self._request("GET", f"{API_BASE}/analyses/{analysis_id}", cancel=cancel)
        return (payload.get("data") or {}).get("attributes") or {}

    def wait_for_analysis(
        self,
        analysis_id: str,
        *,
        timeout: float = 900.0,
        poll_interval: float = 15.0,
        cancel: CancelToken | None = None,
        on_status: Callable[[str], None] | None = None,
    ) -> dict:
        """Poll an analysis until it completes and return its attributes."""
        deadline = self._clock() + timeout
        while True:
            attributes = self.get_analysis(analysis_id, cancel=cancel)
            status = str(attributes.get("status") or "")
            if status == "completed":
                return attributes
            if self._clock() >= deadline:
                raise AnalysisTimeout(
                    "the analysis did not complete within the timeout — "
                    "check the report on the VirusTotal website later"
                )
            if on_status is not None:
                on_status(f"waiting for the analysis ({status or 'queued'})…")
            self._sleep_cancellable(poll_interval, cancel)

    @staticmethod
    def report_url(sha256: str) -> str:
        return f"{GUI_BASE}/{sha256}"

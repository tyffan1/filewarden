"""Exception types raised by FileWarden.

All messages are user-facing and written in Russian.
"""

from __future__ import annotations


class FileWardenError(Exception):
    """Base class for every error raised by this package."""


class ApiError(FileWardenError):
    """The VirusTotal API answered with an error status."""

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.code = code


class ApiKeyError(ApiError):
    """The API key is missing, invalid or not authorized."""


class NotFoundError(ApiError):
    """The requested object does not exist on VirusTotal."""


class UnknownHashError(FileWardenError):
    """The SHA-256 hash is not present in the VirusTotal database."""

    def __init__(self, sha256: str):
        super().__init__(f"hash {sha256} not found on VirusTotal")
        self.sha256 = sha256


class QuotaExceededError(ApiError):
    """The API quota is exhausted (HTTP 429) and retries did not help."""


class NetworkError(FileWardenError):
    """A network problem prevented the request from completing."""


class UploadError(FileWardenError):
    """The file could not be uploaded to VirusTotal."""


class AnalysisTimeout(FileWardenError):
    """The analysis did not finish within the configured timeout."""


class CancelledError(FileWardenError):
    """The operation was cancelled by the user."""

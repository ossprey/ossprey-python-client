class NoPackageManagerException(Exception):
    pass


class MissingPackageException(Exception):
    pass


class InvalidScanModeException(Exception):
    pass


class ScanFailedException(Exception):
    pass


class MaliciousPackageException(Exception):
    pass


class MissingAPIKeyException(Exception):
    pass


class MissingSBOMException(Exception):
    pass


class ScanTimeoutException(Exception):
    pass


class ScanSkippedException(Exception):
    """Raised when the API skips a scan (e.g. quota exhausted)."""

    def __init__(self, message: str = "Scan skipped", reset_at: str | None = None):
        super().__init__(message)
        self.message = message
        self.reset_at = reset_at


class NotAPoetryProjectError(Exception):
    """Raised when the directory doesn't contain a valid poetry project."""

    pass

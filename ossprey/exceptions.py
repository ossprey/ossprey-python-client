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


class PoetryNotFoundError(Exception):
    """Raised when poetry command is not available."""

    pass


class NotAPoetryProjectError(Exception):
    """Raised when the directory doesn't contain a valid poetry project."""

    pass

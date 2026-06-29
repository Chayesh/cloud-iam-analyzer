from enum import Enum


class Severity(str, Enum):
    """
    Severity levels for findings.
    """

    LOW = "LOW"

    MEDIUM = "MEDIUM"

    HIGH = "HIGH"

    CRITICAL = "CRITICAL"
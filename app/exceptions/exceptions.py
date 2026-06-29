class CloudIAMAnalyzerError(Exception):
    """
    Base exception for the application.
    """

    pass


class AWSCollectorError(CloudIAMAnalyzerError):
    """
    Raised when AWS IAM collection fails.
    """

    pass


class PolicyParserError(CloudIAMAnalyzerError):
    """
    Raised when IAM policy parsing fails.
    """

    pass


class EscalationDetectionError(CloudIAMAnalyzerError):
    """
    Raised when privilege escalation detection fails.
    """

    pass


class GraphGenerationError(CloudIAMAnalyzerError):
    """
    Raised when attack graph generation fails.
    """

    pass


class TerraformScannerError(CloudIAMAnalyzerError):
    """
    Raised when Terraform scanning fails.
    """

    pass
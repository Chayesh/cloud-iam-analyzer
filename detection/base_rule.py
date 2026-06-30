from abc import ABC, abstractmethod

from app.models.detection_result import DetectionResult
from app.models.rule_metadata import RuleMetadata


class BaseDetectionRule(ABC):
    """
    Base class for every privilege escalation rule.
    """

    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata:
        """
        Returns metadata describing this rule.
        """
        pass

    @abstractmethod
    def detect(
        self,
        actions: list[str]
    ) -> DetectionResult | None:
        """
        Executes the detection logic.

        Returns a DetectionResult if the rule matches,
        otherwise None.
        """
        pass
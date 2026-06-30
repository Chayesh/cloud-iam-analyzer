from abc import ABC, abstractmethod


class BaseDetectionRule(ABC):
    """
    Base class for all privilege escalation detection rules.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Human-readable rule name.
        """
        pass

    @abstractmethod
    def detect(self, actions: list[str]):
        """
        Execute the rule.

        Returns:
            dict | None
        """
        pass
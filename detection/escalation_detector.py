from app.models.finding import Finding

from detection.rules import load_rules


class EscalationDetector:
    """
    Executes all registered privilege escalation rules
    and converts DetectionResults into Finding objects.
    """

    def __init__(self, permissions: dict[str, list[str]]):

        self.permissions = permissions
        self.rules = load_rules()

    def detect(self) -> list[Finding]:

        findings: list[Finding] = []

        for user, actions in self.permissions.items():

            for rule in self.rules:

                result = rule.detect(actions)

                if result is None:
                    continue

                finding = Finding(
                    metadata=rule.metadata,
                    user=user,
                    chain=result.chain
                )

                findings.append(finding)

        return findings
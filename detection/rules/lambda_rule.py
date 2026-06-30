from detection.base_rule import BaseDetectionRule


class LambdaRule(BaseDetectionRule):
    """
    Detects Lambda + PassRole privilege escalation.
    """

    @property
    def name(self) -> str:
        return "Lambda PassRole Escalation"

    def detect(self, actions: list[str]):

        if (
            "lambda:CreateFunction" in actions
            and "iam:PassRole" in actions
        ):

            return {
                "severity": "HIGH",
                "score": 8.2,
                "chain": [
                    "lambda:CreateFunction",
                    "iam:PassRole",
                    "LambdaExecutionRole",
                    "AdministratorAccess"
                ],
                "fix": [
                    "Restrict Lambda role assignments",
                    "Limit iam:PassRole usage",
                    "Use dedicated Lambda execution roles"
                ]
            }

        return None
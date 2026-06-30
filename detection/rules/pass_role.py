from detection.base_rule import BaseDetectionRule


class PassRoleRule(BaseDetectionRule):
    """
    Detects PassRole + EC2 privilege escalation.
    """

    @property
    def name(self) -> str:
        return "PassRole EC2 Escalation"

    def detect(self, actions: list[str]):

        if (
            "iam:PassRole" in actions
            and "ec2:RunInstances" in actions
        ):

            return {
                "severity": "CRITICAL",
                "score": 9.0,
                "chain": [
                    "iam:PassRole",
                    "ec2:RunInstances",
                    "PrivilegedRole",
                    "AdministratorAccess"
                ],
                "fix": [
                    "Restrict iam:PassRole to specific roles",
                    "Limit EC2 instance launch permissions",
                    "Use IAM conditions for role passing"
                ]
            }

        return None
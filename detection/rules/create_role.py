from detection.base_rule import BaseDetectionRule


class CreateRoleRule(BaseDetectionRule):
    """
    Detects CreateRole -> AttachRolePolicy -> AssumeRole privilege escalation.
    """

    @property
    def name(self) -> str:
        return "Create Role Escalation"

    def detect(self, actions: list[str]):

        if (
            "iam:CreateRole" in actions
            and "iam:AttachRolePolicy" in actions
            and "sts:AssumeRole" in actions
        ):

            return {
                "severity": "CRITICAL",
                "score": 9.5,
                "chain": [
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "sts:AssumeRole",
                    "AdministratorAccess"
                ],
                "fix": [
                    "Remove iam:CreateRole permission",
                    "Restrict iam:AttachRolePolicy to specific roles",
                    "Avoid wildcard '*' permissions",
                    "Use least privilege IAM policies"
                ]
            }

        return None
from detection.base_rule import BaseDetectionRule


class AttachUserPolicyRule(BaseDetectionRule):
    """
    Detects direct AdministratorAccess attachment to a user.
    """

    @property
    def name(self) -> str:
        return "Attach User Policy"

    def detect(self, actions: list[str]):

        if "iam:AttachUserPolicy" in actions:

            return {
                "severity": "CRITICAL",
                "score": 10.0,
                "chain": [
                    "iam:AttachUserPolicy",
                    "AdministratorAccess"
                ],
                "fix": [
                    "Restrict iam:AttachUserPolicy permission",
                    "Require approval workflow for policy attachment",
                    "Audit IAM policy changes"
                ]
            }

        return None
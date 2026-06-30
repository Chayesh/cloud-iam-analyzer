from detection.base_rule import BaseDetectionRule


class PolicyVersionRule(BaseDetectionRule):
    """
    Detects IAM policy version overwrite privilege escalation.
    """

    @property
    def name(self) -> str:
        return "Policy Version Escalation"

    def detect(self, actions: list[str]):

        if (
            "iam:CreatePolicyVersion" in actions
            and "iam:SetDefaultPolicyVersion" in actions
        ):

            return {
                "severity": "HIGH",
                "score": 8.0,
                "chain": [
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion",
                    "PolicyOverwrite",
                    "AdministratorAccess"
                ],
                "fix": [
                    "Restrict policy version modification permissions",
                    "Use IAM change management policies",
                    "Audit IAM policy updates regularly"
                ]
            }

        return None
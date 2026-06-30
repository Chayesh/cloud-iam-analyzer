from detection.base_rule import BaseDetectionRule

from app.models.detection_result import DetectionResult
from app.models.rule_metadata import RuleMetadata
from app.models.severity import Severity


class PolicyVersionRule(BaseDetectionRule):

    @property
    def metadata(self) -> RuleMetadata:

        return RuleMetadata(
            rule_id="AWS-IAM-004",
            title="Policy Version Escalation",
            description="Detects policy version overwrite attacks.",
            severity=Severity.HIGH,
            score=8.0,
            recommendations=[
                "Restrict policy version modification permissions",
                "Use IAM change management",
                "Audit IAM policy updates"
            ],
            references=[]
        )

    def detect(self, actions: list[str]) -> DetectionResult | None:

        if (
            "iam:CreatePolicyVersion" in actions
            and "iam:SetDefaultPolicyVersion" in actions
        ):
            return DetectionResult(
                detected=True,
                chain=[
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion",
                    "PolicyOverwrite",
                    "AdministratorAccess"
                ]
            )

        return None
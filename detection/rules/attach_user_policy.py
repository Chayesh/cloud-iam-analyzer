from detection.base_rule import BaseDetectionRule

from app.models.detection_result import DetectionResult
from app.models.rule_metadata import RuleMetadata
from app.models.severity import Severity


class AttachUserPolicyRule(BaseDetectionRule):

    @property
    def metadata(self) -> RuleMetadata:

        return RuleMetadata(
            rule_id="AWS-IAM-005",
            title="Attach User Policy",
            description="Detects direct attachment of policies to IAM users.",
            severity=Severity.CRITICAL,
            score=10.0,
            recommendations=[
                "Restrict iam:AttachUserPolicy permission",
                "Require approval workflow",
                "Audit IAM policy changes"
            ],
            references=[]
        )

    def detect(self, actions: list[str]) -> DetectionResult | None:

        if "iam:AttachUserPolicy" in actions:

            return DetectionResult(
                detected=True,
                chain=[
                    "iam:AttachUserPolicy",
                    "AdministratorAccess"
                ]
            )

        return None
from detection.base_rule import BaseDetectionRule

from app.models.detection_result import DetectionResult
from app.models.rule_metadata import RuleMetadata
from app.models.severity import Severity


class CreateRoleRule(BaseDetectionRule):

    @property
    def metadata(self) -> RuleMetadata:

        return RuleMetadata(
            rule_id="AWS-IAM-001",
            title="Create Role Privilege Escalation",
            description="Detects CreateRole + AttachRolePolicy + AssumeRole escalation.",
            severity=Severity.CRITICAL,
            score=9.5,
            recommendations=[
                "Remove iam:CreateRole permission",
                "Restrict iam:AttachRolePolicy to specific roles",
                "Avoid wildcard '*' permissions",
                "Use least privilege IAM policies"
            ],
            references=[]
        )

    def detect(self, actions: list[str]) -> DetectionResult | None:

        if (
            "iam:CreateRole" in actions
            and "iam:AttachRolePolicy" in actions
            and "sts:AssumeRole" in actions
        ):
            return DetectionResult(
                detected=True,
                chain=[
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "sts:AssumeRole",
                    "AdministratorAccess"
                ]
            )

        return None
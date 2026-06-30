from detection.base_rule import BaseDetectionRule

from app.models.detection_result import DetectionResult
from app.models.rule_metadata import RuleMetadata
from app.models.severity import Severity


class PassRoleRule(BaseDetectionRule):

    @property
    def metadata(self) -> RuleMetadata:

        return RuleMetadata(
            rule_id="AWS-IAM-002",
            title="PassRole EC2 Escalation",
            description="Detects PassRole combined with EC2 instance creation.",
            severity=Severity.CRITICAL,
            score=9.0,
            recommendations=[
                "Restrict iam:PassRole to specific roles",
                "Limit EC2 instance launch permissions",
                "Use IAM conditions for role passing"
            ],
            references=[]
        )

    def detect(self, actions: list[str]) -> DetectionResult | None:

        if (
            "iam:PassRole" in actions
            and "ec2:RunInstances" in actions
        ):
            return DetectionResult(
                detected=True,
                chain=[
                    "iam:PassRole",
                    "ec2:RunInstances",
                    "PrivilegedRole",
                    "AdministratorAccess"
                ]
            )

        return None
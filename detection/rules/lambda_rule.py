from detection.base_rule import BaseDetectionRule

from app.models.detection_result import DetectionResult
from app.models.rule_metadata import RuleMetadata
from app.models.severity import Severity


class LambdaRule(BaseDetectionRule):

    @property
    def metadata(self) -> RuleMetadata:

        return RuleMetadata(
            rule_id="AWS-IAM-003",
            title="Lambda PassRole Escalation",
            description="Detects Lambda creation with PassRole.",
            severity=Severity.HIGH,
            score=8.2,
            recommendations=[
                "Restrict Lambda role assignments",
                "Limit iam:PassRole usage",
                "Use dedicated Lambda execution roles"
            ],
            references=[]
        )

    def detect(self, actions: list[str]) -> DetectionResult | None:

        if (
            "lambda:CreateFunction" in actions
            and "iam:PassRole" in actions
        ):
            return DetectionResult(
                detected=True,
                chain=[
                    "lambda:CreateFunction",
                    "iam:PassRole",
                    "LambdaExecutionRole",
                    "AdministratorAccess"
                ]
            )

        return None
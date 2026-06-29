import json

from collector.aws_collector import AWSCollector
from parser.policy_parser import extract_actions
from detection.escalation_detector import EscalationDetector

from app.core.logger import logger
from app.exceptions.exceptions import AWSCollectorError


class ScanService:
    """
    Coordinates the IAM scanning workflow.
    """

    def __init__(self):

        self.collector = AWSCollector()

    def collect_permissions(self) -> dict:

        users = self.collector.get_users()

        permissions = {}

        logger.info(f"Users found: {len(users)}")

        for user in users:

            logger.info(f"Processing user: {user}")

            actions = []

            policies = self.collector.get_user_policies(user)

            for policy in policies:

                try:

                    document = self.collector.get_policy_document(
                        policy
                    )

                    actions.extend(
                        extract_actions(document)
                    )

                except AWSCollectorError as e:

                    logger.error(str(e))

            permissions[user] = list(set(actions))

            logger.info(
                f"{user} -> {len(actions)} permissions"
            )

        with open("data/permissions.json", "w") as f:

            json.dump(
                permissions,
                f,
                indent=4
            )

        return permissions

    def scan(self):

        permissions = self.collect_permissions()

        detector = EscalationDetector(
            permissions
        )

        findings = detector.detect()

        return permissions, findings
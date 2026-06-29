import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import settings
from app.core.logger import logger
from app.exceptions.exceptions import AWSCollectorError


class AWSCollector:

    def __init__(self):

        self.iam = boto3.client(
            "iam",
            region_name=settings.AWS_REGION
        )

    # ---------------------------------------
    # Get IAM Users
    # ---------------------------------------

    def get_users(self) -> list[str]:

        users = []

        try:

            response = self.iam.list_users()

            for user in response["Users"]:
                users.append(user["UserName"])

            return users

        except (ClientError, BotoCoreError) as e:

            logger.exception("Unable to retrieve IAM users.")

            raise AWSCollectorError(
                f"Failed to retrieve IAM users: {e}"
            ) from e

    # ---------------------------------------
    # Attached Policies
    # ---------------------------------------

    def get_user_policies(
        self,
        username: str
    ) -> list[str]:

        policies = []

        try:

            response = self.iam.list_attached_user_policies(
                UserName=username
            )

            for policy in response["AttachedPolicies"]:
                policies.append(policy["PolicyArn"])

            return policies

        except (ClientError, BotoCoreError) as e:

            logger.exception(
                f"Unable to retrieve policies for {username}"
            )

            raise AWSCollectorError(
                f"Failed retrieving policies for {username}"
            ) from e

    # ---------------------------------------
    # Policy Document
    # ---------------------------------------

    def get_policy_document(
        self,
        policy_arn: str
    ) -> dict:

        try:

            policy = self.iam.get_policy(
                PolicyArn=policy_arn
            )

            version = policy["Policy"]["DefaultVersionId"]

            document = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )

            return document["PolicyVersion"]["Document"]

        except (ClientError, BotoCoreError) as e:

            logger.exception(
                f"Unable to retrieve policy {policy_arn}"
            )

            raise AWSCollectorError(
                f"Failed retrieving policy document: {policy_arn}"
            ) from e
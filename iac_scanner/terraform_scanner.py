import json
import os


class TerraformScanner:

    def __init__(self, directory):
        self.directory = directory


    def scan(self):

        findings = []

        for file in os.listdir(self.directory):

            if file.endswith(".json"):

                path = os.path.join(self.directory, file)

                with open(path) as f:

                    data = json.load(f)

                    policies = self.extract_policies(data)

                    for policy in policies:

                        result = self.check_escalation(policy)

                        if result:

                            findings.append(result)

        return findings


    def extract_policies(self, data):

        policies = []

        if "Statement" in data:
            policies.append(data)

        return policies


    def check_escalation(self, policy):

        statements = policy.get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        actions = []

        for s in statements:

            if s.get("Effect") == "Allow":

                action = s.get("Action", [])

                if isinstance(action, str):
                    actions.append(action)

                else:
                    actions.extend(action)

        if (
            "iam:CreateRole" in actions and
            "iam:AttachRolePolicy" in actions and
            "sts:AssumeRole" in actions
        ):

            return {
                "severity": "CRITICAL",
                "issue": "Terraform policy allows privilege escalation",
                "chain": [
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "sts:AssumeRole",
                    "AdministratorAccess"
                ]
            }

        return None
class EscalationDetector:

    def __init__(self, permissions):
        self.permissions = permissions


    def detect(self):

        findings = []

        for user, actions in self.permissions.items():

            checks = [
                self.create_role_escalation,
                self.passrole_ec2_escalation,
                self.policy_version_escalation,
                self.lambda_passrole_escalation,
                self.attach_user_policy_escalation
            ]

            for check in checks:

                result = check(actions)

                if result:

                    findings.append({
                        "user": user,
                        "chain": result["chain"],
                        "severity": result["severity"],
                        "score": result["score"],
                        "fix": result["fix"]
                    })

        return findings


    # --------------------------------
    # CreateRole escalation
    # --------------------------------
    def create_role_escalation(self, actions):

        if (
            "iam:CreateRole" in actions and
            "iam:AttachRolePolicy" in actions and
            "sts:AssumeRole" in actions
        ):

            return {
                "chain": [
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "sts:AssumeRole",
                    "AdministratorAccess"
                ],
                "severity": "CRITICAL",
                "score": 9.5,
                "fix": [
                    "Remove iam:CreateRole permission",
                    "Restrict iam:AttachRolePolicy to specific roles",
                    "Avoid wildcard '*' permissions",
                    "Use least privilege IAM policies"
                ]
            }

        return None


    # --------------------------------
    # PassRole + EC2 escalation
    # --------------------------------
    def passrole_ec2_escalation(self, actions):

        if (
            "iam:PassRole" in actions and
            "ec2:RunInstances" in actions
        ):

            return {
                "chain": [
                    "iam:PassRole",
                    "ec2:RunInstances",
                    "PrivilegedRole",
                    "AdministratorAccess"
                ],
                "severity": "CRITICAL",
                "score": 9.0,
                "fix": [
                    "Restrict iam:PassRole to specific roles",
                    "Limit EC2 instance launch permissions",
                    "Use IAM conditions for role passing"
                ]
            }

        return None


    # --------------------------------
    # Policy overwrite escalation
    # --------------------------------
    def policy_version_escalation(self, actions):

        if (
            "iam:CreatePolicyVersion" in actions and
            "iam:SetDefaultPolicyVersion" in actions
        ):

            return {
                "chain": [
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion",
                    "PolicyOverwrite",
                    "AdministratorAccess"
                ],
                "severity": "HIGH",
                "score": 8.0,
                "fix": [
                    "Restrict policy version modification permissions",
                    "Use IAM change management policies",
                    "Audit IAM policy updates regularly"
                ]
            }

        return None


    # --------------------------------
    # Lambda escalation
    # --------------------------------
    def lambda_passrole_escalation(self, actions):

        if (
            "lambda:CreateFunction" in actions and
            "iam:PassRole" in actions
        ):

            return {
                "chain": [
                    "lambda:CreateFunction",
                    "iam:PassRole",
                    "LambdaExecutionRole",
                    "AdministratorAccess"
                ],
                "severity": "HIGH",
                "score": 8.2,
                "fix": [
                    "Restrict Lambda role assignments",
                    "Limit iam:PassRole usage",
                    "Use dedicated Lambda execution roles"
                ]
            }

        return None


    # --------------------------------
    # AttachUserPolicy escalation
    # --------------------------------
    def attach_user_policy_escalation(self, actions):

        if "iam:AttachUserPolicy" in actions:

            return {
                "chain": [
                    "iam:AttachUserPolicy",
                    "AdministratorAccess"
                ],
                "severity": "CRITICAL",
                "score": 10.0,
                "fix": [
                    "Restrict iam:AttachUserPolicy permission",
                    "Require approval workflow for policy attachment",
                    "Audit IAM policy changes"
                ]
            }

        return None
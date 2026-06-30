from detection.rules import load_rules


class EscalationDetector:
    """
    Executes all registered privilege escalation rules.
    """

    def __init__(self, permissions):

        self.permissions = permissions

        self.rules = load_rules()

    def detect(self):

        findings = []

        for user, actions in self.permissions.items():

            for rule in self.rules:

                result = rule.detect(actions)

                if result:

                    result["user"] = user

                    findings.append(result)

        return findings
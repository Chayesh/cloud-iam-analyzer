from detection.escalation_detector import EscalationDetector


def test_detector_finds_create_role():

    permissions = {
        "alice": [
            "iam:CreateRole",
            "iam:AttachRolePolicy",
            "sts:AssumeRole"
        ]
    }

    detector = EscalationDetector(permissions)

    findings = detector.detect()

    assert len(findings) == 1
    assert findings[0].user == "alice"
    assert findings[0].metadata.rule_id == "AWS-IAM-001"
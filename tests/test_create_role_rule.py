from detection.rules.create_role import CreateRoleRule


def test_create_role_detects_escalation():

    rule = CreateRoleRule()

    actions = [
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "sts:AssumeRole"
    ]

    result = rule.detect(actions)

    assert result is not None
    assert result.detected is True


def test_create_role_no_escalation():

    rule = CreateRoleRule()

    actions = [
        "iam:CreateRole"
    ]

    result = rule.detect(actions)

    assert result is None
    
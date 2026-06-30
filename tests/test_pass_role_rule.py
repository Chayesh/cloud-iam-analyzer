from detection.rules.pass_role import PassRoleRule


def test_passrole_detected():

    rule = PassRoleRule()

    actions = [
        "iam:PassRole",
        "ec2:RunInstances"
    ]

    result = rule.detect(actions)

    assert result is not None
    assert result.detected is True


def test_passrole_not_detected():

    rule = PassRoleRule()

    actions = [
        "iam:PassRole"
    ]

    result = rule.detect(actions)

    assert result is None
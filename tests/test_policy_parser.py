from parser.policy_parser import extract_actions


def test_extract_actions_single():

    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:CreateRole",
                "Resource": "*"
            }
        ]
    }

    actions = extract_actions(policy)

    assert "iam:CreateRole" in actions


def test_extract_actions_multiple():

    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreateRole",
                    "iam:AttachRolePolicy"
                ],
                "Resource": "*"
            }
        ]
    }

    actions = extract_actions(policy)

    assert len(actions) == 2
    assert "iam:CreateRole" in actions
    assert "iam:AttachRolePolicy" in actions
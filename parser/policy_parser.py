def extract_actions(policy_document):

    actions = []

    # Get statements
    statements = policy_document.get("Statement", [])

    # Sometimes Statement is a dict instead of list
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        # Only consider allowed permissions
        if statement.get("Effect") == "Allow":

            action = statement.get("Action", [])

            # Sometimes action is a string
            if isinstance(action, str):
                actions.append(action)

            # Sometimes action is a list
            elif isinstance(action, list):
                actions.extend(action)

    return actions
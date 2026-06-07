"""
scenario_generator.py — Future Outcome Generator

For each proposed action, generates a list of possible
outcomes that would result from taking that action.

    Action
       ↓
    What could happen?
       ↓
    Possible Outcomes
"""


OUTCOME_TEMPLATES = {

    "block_user": {
        "description": "Immediately block all user access",
        "outcomes": [
            "Threat actor access eliminated",
            "Active deployments may fail",
            "Dependent services could experience downtime",
            "Team workflows disrupted",
            "Evidence preserved at point of block"
        ]
    },

    "monitor_user": {
        "description": "Continue monitoring without intervention",
        "outcomes": [
            "Threat actor retains full access",
            "Additional data exfiltration possible",
            "No business disruption",
            "More evidence collected over time",
            "Risk of escalation remains"
        ]
    },

    "temporary_restriction": {
        "description": "Restrict elevated privileges, maintain basic access",
        "outcomes": [
            "Privileged operations blocked",
            "Basic workflows continue",
            "Evidence preserved and collected",
            "Partial threat containment",
            "Analyst review initiated"
        ]
    }
}


def generate_scenarios(user_context):
    """
    Generate all possible action scenarios with their outcomes.

    Args:
        user_context: dict with user info from the Digital Twin

    Returns:
        list of scenario dicts
    """
    user = user_context.get("user", "Unknown")
    scenarios = []

    for action, template in OUTCOME_TEMPLATES.items():
        scenario = {
            "action": action,
            "description": template["description"],
            "target_user": user,
            "outcomes": _contextualize(template["outcomes"], user_context)
        }
        scenarios.append(scenario)

    return scenarios


def _contextualize(outcomes, user_context):
    """Add context-specific details to generic outcomes."""
    user = user_context.get("user", "Unknown")
    dept = user_context.get("department", "Unknown")
    services = user_context.get("services", [])

    contextualized = []
    for outcome in outcomes:
        detail = outcome

        if "deployments" in outcome.lower() and services:
            detail += f" (affects: {', '.join(services[:3])})"

        if "workflows" in outcome.lower() and dept:
            detail += f" ({dept} team)"

        contextualized.append(detail)

    return contextualized

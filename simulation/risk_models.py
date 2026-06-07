"""
risk_models.py — Risk Scoring Logic

Calculates security, business, and compliance risk scores
for a proposed action based on Digital Twin context.

Scores are 0-100 where:
    0  = No risk
    100 = Maximum risk
"""


def ai_toolkit_risk_score(action, user_context):
    """
    Calculate risk using the Splunk AI Toolkit.
    Blends with rule-based security/business/compliance risk depending on the action.
    """
    try:
        from splunk.ai_toolkit import get_ai_toolkit
        toolkit = get_ai_toolkit()

        # Enforce action in user context
        context_copy = dict(user_context)
        context_copy["action"] = action

        # Get AI Toolkit score
        ai_res = toolkit.score_risk(context_copy)
        return ai_res.get("risk_score", 50)
    except Exception as e:
        print(f"  [RiskModels] AI Toolkit scoring failed: {e}")
        return None


def security_risk(action, user_context):
    """
    How much security risk remains after taking this action?

    Block user     → low security risk (threat neutralized)
    Monitor user   → high security risk (threat continues)
    Restrict user  → moderate security risk (partial containment)
    """
    alert_count = len(user_context.get("alerts", []))
    has_sensitive = user_context.get("touches_sensitive", False)

    base = 0

    if action == "block_user":
        base = 5
        # Blocking eliminates most risk
        if alert_count > 3:
            base += 5  # Slight residual risk from already-exfiltrated data

    elif action == "monitor_user":
        base = 40
        base += alert_count * 8
        if has_sensitive:
            base += 20

    elif action == "temporary_restriction":
        base = 15
        base += alert_count * 3
        if has_sensitive:
            base += 10

    rule_score = min(base, 100)
    ai_score = ai_toolkit_risk_score(action, user_context)
    if ai_score is not None:
        # Blend: 70% rule-based, 30% AI Toolkit based
        if action == "block_user":
            return int(0.8 * rule_score + 0.2 * ai_score)
        elif action == "monitor_user":
            return int(0.6 * rule_score + 0.4 * ai_score)
        else:
            return int(0.7 * rule_score + 0.3 * ai_score)
    return rule_score


def business_risk(action, user_context):
    """
    How much business disruption does this action cause?

    Block user     → high if user is critical
    Monitor user   → low disruption
    Restrict user  → moderate disruption
    """
    criticality = user_context.get("criticality", "Low")
    service_count = len(user_context.get("services", []))
    blast_radius = user_context.get("blast_radius", 0)

    criticality_scores = {
        "Very High": 50,
        "High": 30,
        "Medium": 15,
        "Low": 5
    }
    crit_base = criticality_scores.get(criticality, 10)

    if action == "block_user":
        base = crit_base
        base += min(service_count * 4, 30)
        base += min(blast_radius * 2, 20)

    elif action == "monitor_user":
        base = 3
        # Monitoring has almost no business impact

    elif action == "temporary_restriction":
        base = int(crit_base * 0.4)
        base += min(service_count * 1, 10)

    else:
        base = 10

    rule_score = min(base, 100)
    ai_score = ai_toolkit_risk_score(action, user_context)
    if ai_score is not None:
        # Blend: 80% rule-based, 20% AI Toolkit based
        return int(0.8 * rule_score + 0.2 * ai_score)
    return rule_score


def compliance_risk(action, user_context):
    """
    How much compliance risk does this action carry?

    Block without evidence  → compliance risk
    Monitor without logging → compliance risk
    Restrict + preserve     → low compliance risk
    """
    policy_count = len(user_context.get("policies", []))
    has_critical_policies = any(
        p in ["GDPR", "Access Control", "Data Retention"]
        for p in user_context.get("policies", [])
    )

    if action == "block_user":
        base = 10
        if has_critical_policies:
            base += 15  # Must preserve evidence before blocking
        if policy_count == 0:
            base = 5

    elif action == "monitor_user":
        base = 20
        if has_critical_policies:
            base += 25  # Delay may violate response requirements

    elif action == "temporary_restriction":
        base = 5
        if has_critical_policies:
            base += 5  # Restriction + evidence preservation is ideal
        # This action inherently includes evidence preservation

    else:
        base = 15

    rule_score = min(base, 100)
    ai_score = ai_toolkit_risk_score(action, user_context)
    if ai_score is not None:
        # Blend: 80% rule-based, 20% AI Toolkit based
        return int(0.8 * rule_score + 0.2 * ai_score)
    return rule_score

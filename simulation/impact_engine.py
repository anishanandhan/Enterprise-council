"""
impact_engine.py — Impact Simulation Engine

The "wow" feature.

Instead of agents just arguing, we simulate the future:

    Proposed Action
         ↓
    Risk Models (security, business, compliance)
         ↓
    Scenario Outcomes
         ↓
    Impact Scores
         ↓
    Best Action Selected

This transforms the council from discussion to decision intelligence.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulation.risk_models import security_risk, business_risk, compliance_risk
from simulation.scenario_generator import generate_scenarios
from services.graph_query import (
    get_user_services, get_user_alerts, get_criticality,
    get_user_department, get_affected_systems, get_policies_for_event
)


ACTIONS = ["block_user", "monitor_user", "temporary_restriction"]


def build_user_context(incident, graph):
    """
    Pull everything we know about this user from the Digital Twin,
    and enrich it with Splunk AI Toolkit anomaly scores.
    """
    user = incident.get("user", "Unknown")
    event = incident.get("event", "")
    severity = incident.get("severity", "Medium")

    services = get_user_services(graph, user)
    impact = get_affected_systems(graph, user)

    # Enrich with anomaly detection results from AI Toolkit
    anomaly_score = 0
    try:
        from splunk.ai_toolkit import get_ai_toolkit
        toolkit = get_ai_toolkit()
        detect = toolkit.apply_anomaly_model(index="security")
        anomaly_count = detect.get("anomaly_count", 0)

        # Baseline anomaly score on incident severity
        severity_bases = {"Critical": 80, "High": 55, "Medium": 30, "Low": 10}
        anomaly_score = severity_bases.get(severity, 20)

        # Add variance based on detected anomalies count
        anomaly_score = min(anomaly_score + (anomaly_count * 5), 100)
    except Exception as e:
        print(f"  [ImpactEngine] Anomaly detection failed: {e}")

    return {
        "user": user,
        "event": event,
        "services": services,
        "alerts": get_user_alerts(graph, user),
        "criticality": get_criticality(graph, user),
        "department": get_user_department(graph, user),
        "blast_radius": impact["total_impact"],
        "touches_sensitive": any(s in services for s in ["CustomerDB", "AWS"]),
        "policies": get_policies_for_event(graph, event),
        "anomaly_score": anomaly_score
    }


def simulate(incident, graph):
    """
    Simulate all possible actions and return ranked results.

    Returns:
        dict with simulations for each action and the recommended best action
    """
    context = build_user_context(incident, graph)
    scenarios = generate_scenarios(context)

    simulations = []

    for action in ACTIONS:
        sec = security_risk(action, context)
        biz = business_risk(action, context)
        comp = compliance_risk(action, context)
        # Normalize total risk back to 0-100% range by averaging
        total = int((sec + biz + comp) / 3)

        # Find matching scenario
        scenario = next((s for s in scenarios if s["action"] == action), None)

        simulations.append({
            "action": action,
            "description": scenario["description"] if scenario else action,
            "security_risk": sec,
            "business_risk": biz,
            "compliance_risk": comp,
            "total_risk": total,
            "outcomes": scenario["outcomes"] if scenario else []
        })

    # Sort by total risk (lowest = best)
    simulations.sort(key=lambda s: s["total_risk"])

    best = simulations[0]

    return {
        "user_context": context,
        "simulations": simulations,
        "recommended_action": best["action"],
        "recommended_description": best["description"],
        "recommended_total_risk": best["total_risk"]
    }


if __name__ == "__main__":
    from splunk.twin_sync import sync_twin

    print("\n  Impact Simulation Test")
    print("  " + "-" * 50)

    twin = sync_twin()

    incident = {
        "user": "John",
        "event": "Privilege Escalation",
        "severity": "Critical"
    }

    result = simulate(incident, twin)

    print(f"\n  User: {result['user_context']['user']}")
    print(f"  Criticality: {result['user_context']['criticality']}")
    print(f"  Blast Radius: {result['user_context']['blast_radius']} systems")
    print()

    for sim in result["simulations"]:
        print(f"  Action: {sim['action']}")
        print(f"    Security Risk:   {sim['security_risk']}%")
        print(f"    Business Risk:   {sim['business_risk']}%")
        print(f"    Compliance Risk: {sim['compliance_risk']}%")
        print(f"    Total Risk:      {sim['total_risk']}%")
        print()

    print(f"  ✓ Recommended: {result['recommended_action']}")
    print(f"    Total Risk:  {result['recommended_total_risk']}%")

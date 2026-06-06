"""
agent_planner.py — Dynamic Agent Factory

Instead of a fixed council, the planner creates the right
agents for each incident based on classification.

    Incident
       ↓
    Classify
       ↓
    Agent Planner
       ↓
    Dynamic Council
"""

from agents.security_agent import SecurityAgent
from agents.infrastructure_agent import InfrastructureAgent
from agents.compliance_agent import ComplianceAgent
from agents.business_agent import BusinessAgent
from orchestrator.incident_classifier import classify


# Agent registry — maps domain names to agent classes
AGENT_REGISTRY = {
    "security":       SecurityAgent,
    "infrastructure": InfrastructureAgent,
    "compliance":     ComplianceAgent,
    "business":       BusinessAgent,
}


def plan_council(incident):
    """
    Analyze the incident and assemble the right council.

    Returns:
        dict with classification info and instantiated agents
    """
    # Classify the incident
    classification = classify(incident)

    # Select agents based on required domains
    selected_agents = []
    for domain in classification["domains"]:
        agent_class = AGENT_REGISTRY.get(domain)
        if agent_class:
            selected_agents.append(agent_class())

    return {
        "classification": classification,
        "agents": selected_agents,
        "council_size": len(selected_agents)
    }

"""
conftest.py — Shared Test Fixtures for Enterprise Council AI

Provides reusable test data, mock objects, and graph fixtures
that mirror the production Digital Twin topology.
"""

import sys
import os
import pytest

# Ensure the project root is on the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from twin.graph_model import EnterpriseGraph
from twin.entities import User, Device, Service, Database, Department, Alert, Policy
from agents.base import AgentOpinion


# ── Graph Fixtures ───────────────────────────────────────────────

@pytest.fixture
def empty_graph():
    """An empty EnterpriseGraph with no nodes or edges."""
    return EnterpriseGraph()


@pytest.fixture
def sample_graph():
    """
    A populated EnterpriseGraph matching the NovaTech Solutions demo scenario.
    Contains users, devices, services, alerts, departments, and policies.
    """
    graph = EnterpriseGraph()

    # Users
    john = User(name="John")
    alice = User(name="Alice")
    bob = User(name="Bob")

    # Devices
    macbook = Device(name="MacBook-Pro")
    workstation = Device(name="Linux-Workstation")

    # Services
    aws = Service(name="AWS")
    kubernetes = Service(name="Kubernetes")
    deploy_svc = Service(name="Deployment-Service")
    api_gw = Service(name="API-Gateway")

    # Databases
    customer_db = Database(name="CustomerDB")

    # Departments
    engineering = Department(name="Engineering")
    security_dept = Department(name="Security")

    # Alerts
    vpn_alert = Alert(name="VPN Anomaly")
    priv_esc = Alert(name="Privilege Escalation")
    large_dl = Alert(name="Large Download")

    # Policies
    pci = Policy(name="PCI-DSS")
    gdpr = Policy(name="GDPR")
    access_ctrl = Policy(name="Access Control")

    # Add all nodes
    for entity in [john, alice, bob, macbook, workstation, aws, kubernetes,
                   deploy_svc, api_gw, customer_db, engineering, security_dept,
                   vpn_alert, priv_esc, large_dl, pci, gdpr, access_ctrl]:
        graph.add_node(entity)

    # Add edges — User relationships
    graph.add_edge("John", "MacBook-Pro", "USES")
    graph.add_edge("John", "AWS", "ACCESSES")
    graph.add_edge("John", "CustomerDB", "ACCESSES")
    graph.add_edge("John", "Kubernetes", "ACCESSES")
    graph.add_edge("John", "Deployment-Service", "ACCESSES")
    graph.add_edge("John", "Engineering", "BELONGS_TO")
    graph.add_edge("Alice", "Linux-Workstation", "USES")
    graph.add_edge("Alice", "AWS", "ACCESSES")
    graph.add_edge("Alice", "Security", "BELONGS_TO")

    # Add edges — Alert targeting
    graph.add_edge("VPN Anomaly", "John", "TARGETS")
    graph.add_edge("Privilege Escalation", "John", "TARGETS")
    graph.add_edge("Large Download", "John", "TARGETS")

    # Add edges — Service dependencies
    graph.add_edge("Kubernetes", "AWS", "DEPENDS_ON")
    graph.add_edge("Deployment-Service", "Kubernetes", "DEPENDS_ON")
    graph.add_edge("API-Gateway", "Kubernetes", "DEPENDS_ON")

    # Add edges — Policy governance
    graph.add_edge("PCI-DSS", "Large Download", "GOVERNS")
    graph.add_edge("GDPR", "Privilege Escalation", "GOVERNS")
    graph.add_edge("Access Control", "Privilege Escalation", "GOVERNS")

    return graph


# ── Incident Fixtures ────────────────────────────────────────────

@pytest.fixture
def critical_incident():
    """A critical-severity privilege escalation incident for John."""
    return {
        "user": "John",
        "event": "Privilege Escalation",
        "severity": "Critical"
    }


@pytest.fixture
def medium_incident():
    """A medium-severity VPN login event."""
    return {
        "user": "Alice",
        "event": "VPN Login",
        "severity": "Medium"
    }


@pytest.fixture
def unknown_incident():
    """An incident with an unrecognized event type."""
    return {
        "user": "Bob",
        "event": "Unknown Strange Event",
        "severity": "Low"
    }


# ── Agent Opinion Fixtures ───────────────────────────────────────

@pytest.fixture
def sample_opinions():
    """A list of AgentOpinion instances simulating a council assessment."""
    return [
        AgentOpinion(
            agent_name="Security Agent",
            risk_level="Critical",
            recommendation="Block User",
            confidence=0.92,
            reasoning="Multiple alerts detected. Immediate containment required."
        ),
        AgentOpinion(
            agent_name="Infrastructure Agent",
            risk_level="High",
            recommendation="Monitor User",
            confidence=0.78,
            reasoning="Blocking the user may disrupt active deployments."
        ),
        AgentOpinion(
            agent_name="Compliance Agent",
            risk_level="High",
            recommendation="Restrict Access",
            confidence=0.85,
            reasoning="Evidence must be preserved before any containment action."
        ),
        AgentOpinion(
            agent_name="Business Agent",
            risk_level="Medium",
            recommendation="Monitor User",
            confidence=0.70,
            reasoning="John is critical to ongoing operations. Full block is disruptive."
        ),
    ]


# ── User Context Fixtures ───────────────────────────────────────

@pytest.fixture
def sample_user_context():
    """A user context dictionary matching the build_user_context output structure."""
    return {
        "user": "John",
        "event": "Privilege Escalation",
        "services": ["AWS", "CustomerDB", "Kubernetes", "Deployment-Service"],
        "alerts": ["VPN Anomaly", "Privilege Escalation", "Large Download"],
        "criticality": "Very High",
        "department": "Engineering",
        "blast_radius": 7,
        "touches_sensitive": True,
        "policies": ["GDPR", "Access Control"],
        "anomaly_score": 85
    }

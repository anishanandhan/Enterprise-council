"""
test_twin.py — Digital Twin Graph Model Tests

Validates the EnterpriseGraph class, entity node creation,
edge relationships, and graph query interface functions.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from twin.graph_model import EnterpriseGraph
from twin.entities import User, Device, Service, Database, Department, Alert, Policy
from services.graph_query import (
    get_user_services, get_user_alerts, get_criticality,
    get_user_department, get_affected_systems, get_policies_for_event,
    get_user_devices
)


class TestEnterpriseGraph:
    """Tests for the EnterpriseGraph wrapper class."""

    @pytest.mark.unit
    def test_empty_graph_has_no_nodes(self, empty_graph):
        summary = empty_graph.summary()
        assert summary["nodes"] == 0
        assert summary["edges"] == 0

    @pytest.mark.unit
    def test_add_single_node(self, empty_graph):
        user = User(name="TestUser")
        empty_graph.add_node(user)
        summary = empty_graph.summary()
        assert summary["nodes"] == 1
        assert summary["edges"] == 0

    @pytest.mark.unit
    def test_add_edge_creates_relationship(self, empty_graph):
        user = User(name="John")
        service = Service(name="AWS")
        empty_graph.add_node(user)
        empty_graph.add_node(service)
        empty_graph.add_edge("John", "AWS", "ACCESSES")
        summary = empty_graph.summary()
        assert summary["nodes"] == 2
        assert summary["edges"] == 1

    @pytest.mark.unit
    def test_edge_stores_relation_attribute(self, empty_graph):
        user = User(name="John")
        service = Service(name="AWS")
        empty_graph.add_node(user)
        empty_graph.add_node(service)
        empty_graph.add_edge("John", "AWS", "ACCESSES")
        edge_data = empty_graph.G.edges["John", "AWS"]
        assert edge_data["relation"] == "ACCESSES"

    @pytest.mark.unit
    def test_sample_graph_has_expected_topology(self, sample_graph):
        summary = sample_graph.summary()
        assert summary["nodes"] > 10, "Sample graph should have at least 10 nodes"
        assert summary["edges"] > 10, "Sample graph should have at least 10 edges"

    @pytest.mark.unit
    def test_directed_graph_type(self, sample_graph):
        import networkx as nx
        assert isinstance(sample_graph.G, nx.DiGraph), "Graph should be directed"


class TestEntityTypes:
    """Tests for the entity dataclass definitions."""

    @pytest.mark.unit
    def test_user_entity(self):
        user = User(name="TestUser")
        assert user.name == "TestUser"

    @pytest.mark.unit
    def test_device_entity(self):
        device = Device(name="MacBook")
        assert device.name == "MacBook"

    @pytest.mark.unit
    def test_service_entity(self):
        service = Service(name="AWS")
        assert service.name == "AWS"

    @pytest.mark.unit
    def test_database_entity(self):
        db = Database(name="CustomerDB")
        assert db.name == "CustomerDB"

    @pytest.mark.unit
    def test_department_entity(self):
        dept = Department(name="Engineering")
        assert dept.name == "Engineering"

    @pytest.mark.unit
    def test_alert_entity(self):
        alert = Alert(name="VPN Anomaly")
        assert alert.name == "VPN Anomaly"

    @pytest.mark.unit
    def test_policy_entity(self):
        policy = Policy(name="PCI-DSS")
        assert policy.name == "PCI-DSS"


class TestGraphQueries:
    """Tests for the graph query layer (services/graph_query.py)."""

    @pytest.mark.unit
    def test_get_user_services_returns_list(self, sample_graph):
        services = get_user_services(sample_graph, "John")
        assert isinstance(services, list)
        assert len(services) >= 3, "John should access AWS, CustomerDB, Kubernetes, Deployment-Service"

    @pytest.mark.unit
    def test_get_user_services_contains_aws(self, sample_graph):
        services = get_user_services(sample_graph, "John")
        assert "AWS" in services

    @pytest.mark.unit
    def test_get_user_services_nonexistent_user(self, sample_graph):
        services = get_user_services(sample_graph, "NonExistentUser")
        assert services == []

    @pytest.mark.unit
    def test_get_user_alerts_returns_list(self, sample_graph):
        alerts = get_user_alerts(sample_graph, "John")
        assert isinstance(alerts, list)
        assert len(alerts) >= 2, "John should have multiple alerts"

    @pytest.mark.unit
    def test_get_user_alerts_includes_privilege_escalation(self, sample_graph):
        alerts = get_user_alerts(sample_graph, "John")
        assert "Privilege Escalation" in alerts

    @pytest.mark.unit
    def test_get_criticality_very_high(self, sample_graph):
        criticality = get_criticality(sample_graph, "John")
        assert criticality in ("Very High", "High"), "John with many critical connections should be High or Very High"

    @pytest.mark.unit
    def test_get_criticality_low_for_unknown_user(self, sample_graph):
        criticality = get_criticality(sample_graph, "UnknownUser")
        assert criticality == "Low"

    @pytest.mark.unit
    def test_get_user_department(self, sample_graph):
        dept = get_user_department(sample_graph, "John")
        assert dept == "Engineering"

    @pytest.mark.unit
    def test_get_user_department_none_for_unknown(self, sample_graph):
        dept = get_user_department(sample_graph, "UnknownUser")
        assert dept is None

    @pytest.mark.unit
    def test_get_affected_systems_structure(self, sample_graph):
        result = get_affected_systems(sample_graph, "John")
        assert "direct" in result
        assert "downstream" in result
        assert "total_impact" in result
        assert isinstance(result["direct"], list)
        assert isinstance(result["downstream"], list)
        assert result["total_impact"] == len(result["direct"]) + len(result["downstream"])

    @pytest.mark.unit
    def test_get_affected_systems_has_downstream(self, sample_graph):
        result = get_affected_systems(sample_graph, "John")
        assert result["total_impact"] > len(result["direct"]), \
            "John's services should have downstream dependencies"

    @pytest.mark.unit
    def test_get_policies_for_event(self, sample_graph):
        policies = get_policies_for_event(sample_graph, "Privilege Escalation")
        assert isinstance(policies, list)
        assert len(policies) >= 1, "Privilege Escalation should be governed by at least one policy"

    @pytest.mark.unit
    def test_get_policies_for_unknown_event(self, sample_graph):
        policies = get_policies_for_event(sample_graph, "Unknown Event")
        assert policies == []

    @pytest.mark.unit
    def test_get_user_devices(self, sample_graph):
        devices = get_user_devices(sample_graph, "John")
        assert isinstance(devices, list)
        # John uses MacBook-Pro
        assert "MacBook-Pro" in devices

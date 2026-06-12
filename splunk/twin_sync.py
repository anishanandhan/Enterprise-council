"""
twin_sync.py — Digital Twin Synchronization

Fetches latest events from Splunk (or CSV fallback) and
rebuilds or updates the Digital Twin graph.

    Splunk
       ↓
    Latest Events
       ↓
    Graph Update

This is where the twin becomes "living".
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from splunk.splunk_client import get_client
from splunk.queries import SECURITY_EVENTS, INFRA_EVENTS, BUSINESS_EVENTS, COMPLIANCE_EVENTS
from twin.graph_model import EnterpriseGraph
from twin.entities import User, Device, Service, Database, Department, Alert, Policy


def verify_event_signature(row):
    """
    Cryptographically verify the integrity of the telemetry event row to prevent Graph Poisoning.
    Simulates identity verification and cryptographic signatures (e.g. SPIFFE/SPIRE context) 
    associated with incoming Splunk logs.
    """
    import os
    import hmac
    import hashlib

    # If telemetry signatures are required, validate the signature or token
    require_sigs = os.environ.get("REQUIRE_TELEMETRY_SIGNATURES", "false").lower() == "true"
    if not require_sigs:
        return True

    # Critical fields determining topology relationship
    fields = [row.get("user", ""), row.get("device", ""), row.get("event", ""), row.get("service", ""), row.get("department", "")]
    payload = "|".join(filter(None, fields))
    
    # We expect a telemetry signature header or field
    received_sig = row.get("_telemetry_signature")
    if not received_sig:
        print(f"  [Security Alert] Event missing cryptographic signature. Skipping to prevent Graph Poisoning: {row}")
        return False
        
    # Verify signature using shared secret (mocking HSM/SPIFFE identity vault)
    secret = b"spiffe_twin_sync_secret_key_2026"
    expected_sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(received_sig, expected_sig):
        print(f"  [Security Alert] Cryptographic signature mismatch! Target event payload: {payload}. Skipping to prevent spoofing.")
        return False
        
    return True


def sync_twin():
    """
    Build the Digital Twin from Splunk data (or CSV fallback).

    Returns a fully populated EnterpriseGraph.
    """
    client = get_client()
    graph = EnterpriseGraph()

    # 1. Business events -> Users, Departments
    print("  [Sync] Fetching business events...")
    business_events = client.search(BUSINESS_EVENTS)
    for row in business_events:
        if not verify_event_signature(row):
            continue
        user = row.get("user", "")
        dept = row.get("department", "")
        if user and not graph.G.has_node(user):
            graph.add_node(User(name=user))
        if dept and not graph.G.has_node(dept):
            graph.add_node(Department(name=dept))
        if user and dept:
            graph.add_edge(user, dept, relation="BELONGS_TO")

    # 2. Security events -> Alerts, Devices
    print("  [Sync] Fetching security events...")
    security_events = client.search(SECURITY_EVENTS)
    for row in security_events:
        if not verify_event_signature(row):
            continue
        user = row.get("user", "")
        device = row.get("device", "")
        event = row.get("event", "")

        if user and not graph.G.has_node(user):
            graph.add_node(User(name=user))
        if device and not graph.G.has_node(device):
            graph.add_node(Device(name=device))
        if event and not graph.G.has_node(event):
            graph.add_node(Alert(name=event))

        if user and device:
            graph.add_edge(user, device, relation="USES")
        if event and user:
            graph.add_edge(event, user, relation="TARGETS")

    # 3. Infrastructure events -> Services, Databases
    print("  [Sync] Fetching infrastructure events...")
    infra_events = client.search(INFRA_EVENTS)
    for row in infra_events:
        if not verify_event_signature(row):
            continue
        service = row.get("service", "")
        event = row.get("event", "")

        if service:
            if "DB" in service.upper():
                if not graph.G.has_node(service):
                    graph.add_node(Database(name=service))
            else:
                if not graph.G.has_node(service):
                    graph.add_node(Service(name=service))

        if event and not graph.G.has_node(event):
            graph.add_node(Alert(name=event))

        if event and service:
            graph.add_edge(event, service, relation="AFFECTS")

    # 4. Compliance events -> Policies
    print("  [Sync] Fetching compliance events...")
    compliance_events = client.search(COMPLIANCE_EVENTS)
    for row in compliance_events:
        if not verify_event_signature(row):
            continue
        event = row.get("event", "")
        policy = row.get("policy", "")

        if event and not graph.G.has_node(event):
            graph.add_node(Alert(name=event))
        if policy and not graph.G.has_node(policy):
            graph.add_node(Policy(name=policy))

        if policy and event:
            graph.add_edge(policy, event, relation="GOVERNS")

    # 5. Wire known service dependencies
    _wire_dependencies(graph)

    return graph


def _wire_dependencies(graph):
    """Add known infrastructure relationships."""
    extra_services = ["VPN", "Kubernetes", "AWS", "GitHub"]
    for s in extra_services:
        if not graph.G.has_node(s):
            graph.add_node(Service(name=s))

    known_edges = [
        ("John", "Kubernetes", "ACCESSES"),
        ("John", "VPN", "ACCESSES"),
        ("John", "AWS", "ACCESSES"),
        ("John", "GitHub", "ACCESSES"),
        ("John", "CustomerDB", "ACCESSES"),
        ("CustomerDB", "API-Gateway", "USES"),
        ("Deployment-Service", "CustomerDB", "USES"),
        ("API-Gateway", "CustomerDB", "USES"),
        ("Alice", "CustomerDB", "ACCESSES"),
        ("Alice", "API-Gateway", "ACCESSES"),
        ("Alice", "AWS", "ACCESSES"),
        ("Alice", "MacBook-Pro-01", "USES"),
        ("Bob", "VPN", "ACCESSES"),
        ("Bob", "Kubernetes", "ACCESSES"),
        ("Bob", "MacBook-Pro-01", "USES"),
        ("Bob", "Deployment-Service", "ACCESSES"),
        ("Engineering", "AWS", "USES"),
        ("Operations", "Kubernetes", "USES"),
        ("Security", "VPN", "USES"),
    ]
    for src, tgt, rel in known_edges:
        if graph.G.has_node(src) or graph.G.has_node(tgt):
            graph.add_edge(src, tgt, relation=rel)


if __name__ == "__main__":
    print("\n  Twin Sync Test")
    print("  " + "-" * 40)
    twin = sync_twin()
    summary = twin.summary()
    print(f"\n  Twin synced from Splunk")
    print(f"  Nodes: {summary['nodes']}")
    print(f"  Edges: {summary['edges']}")

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
from twin.graph_model import EnterpriseGraph
from twin.entities import User, Device, Service, Database, Department, Alert, Policy

def build_twin():
    graph = EnterpriseGraph()
    
    datasets_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'datasets')
    
    # Read CSVs
    business_df = pd.read_csv(os.path.join(datasets_dir, 'business_logs.csv'))
    security_df = pd.read_csv(os.path.join(datasets_dir, 'security_logs.csv'))
    infra_df = pd.read_csv(os.path.join(datasets_dir, 'infra_logs.csv'))
    compliance_df = pd.read_csv(os.path.join(datasets_dir, 'compliance_logs.csv'))

    # 1. Business Logs -> Create Users, Departments
    for _, row in business_df.iterrows():
        user = row['user']
        dept = row['department']
        if not graph.G.has_node(user):
            graph.add_node(User(name=user))
        if not graph.G.has_node(dept):
            graph.add_node(Department(name=dept))
        graph.add_edge(user, dept, relation="BELONGS_TO")

    # 2. Security Logs -> Create Alerts, Devices
    for _, row in security_df.iterrows():
        user = row['user']
        device = row['device']
        event = row['event']
        
        if not graph.G.has_node(user):
            graph.add_node(User(name=user))
        if not graph.G.has_node(device):
            graph.add_node(Device(name=device))
        if not graph.G.has_node(event):
            graph.add_node(Alert(name=event))
            
        graph.add_edge(user, device, relation="USES")
        graph.add_edge(event, user, relation="TARGETS")

    # 3. Infra Logs -> Create Services, Databases
    for _, row in infra_df.iterrows():
        service = row['service']
        event = row['event']
        
        if "DB" in service:
            if not graph.G.has_node(service):
                graph.add_node(Database(name=service))
        else:
            if not graph.G.has_node(service):
                graph.add_node(Service(name=service))
                
        if not graph.G.has_node(event):
            graph.add_node(Alert(name=event))
            
        graph.add_edge(event, service, relation="AFFECTS")

    # 4. Compliance Logs -> Create Policies, Alerts
    for _, row in compliance_df.iterrows():
        event = row['event']
        policy = row['policy']
        
        if not graph.G.has_node(event):
            graph.add_node(Alert(name=event))
        if not graph.G.has_node(policy):
            graph.add_node(Policy(name=policy))
            
        graph.add_edge(policy, event, relation="GOVERNS")

    # Add additional context nodes
    extra_services = ["VPN", "Kubernetes", "AWS", "GitHub"]
    for s in extra_services:
        graph.add_node(Service(name=s))

    # Add relationships
    extra_edges = [
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
        ("Security", "VPN", "USES")
    ]
    for src, tgt, rel in extra_edges:
        graph.add_edge(src, tgt, relation=rel)

    return graph

if __name__ == "__main__":
    twin = build_twin()
    
    print("John -> Engineering")
    print("John -> VPN")
    print("John -> CustomerDB")
    print("Privilege Escalation -> John")
    print("CustomerDB -> API Gateway")
    print()
    
    print("Enterprise Graph Created")
    summary = twin.summary()
    print(f"Nodes: {summary['nodes']}")
    print(f"Edges: {summary['edges']}")

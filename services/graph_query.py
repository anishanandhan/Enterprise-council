"""
Graph Query Layer — The bridge between Agents and the Digital Twin.

Agents never touch the graph directly.
They ask questions through this layer.

    Agent
       ↓
    Graph Query Layer
       ↓
    Digital Twin
"""


def get_user_department(graph, user):
    """What department does this user belong to?"""
    for src, tgt, data in graph.G.edges(data=True):
        if src == user and data.get("relation") == "BELONGS_TO":
            return tgt
    return None


def get_user_services(graph, user):
    """What services/systems does this user access?"""
    services = []
    for src, tgt, data in graph.G.edges(data=True):
        if src == user and data.get("relation") in ("USES", "ACCESSES"):
            services.append(tgt)
    return services


def get_user_alerts(graph, user):
    """What alerts target this user?"""
    alerts = []
    for src, tgt, data in graph.G.edges(data=True):
        if data.get("relation") == "TARGETS" and tgt == user:
            alerts.append(src)
    return alerts


def get_criticality(graph, user):
    """How critical is this user based on their connections?"""
    services = get_user_services(graph, user)
    alerts = get_user_alerts(graph, user)

    critical_systems = {"CustomerDB", "AWS", "Kubernetes", "Deployment-Service", "API-Gateway"}
    critical_connections = [s for s in services if s in critical_systems]

    if len(critical_connections) >= 3 and len(alerts) >= 2:
        return "Very High"
    elif len(critical_connections) >= 2:
        return "High"
    elif len(critical_connections) >= 1:
        return "Medium"
    else:
        return "Low"


def get_affected_systems(graph, user):
    """If we block this user, what systems are affected downstream?"""
    direct = get_user_services(graph, user)

    downstream = set()
    for svc in direct:
        for src, tgt, data in graph.G.edges(data=True):
            if src == svc and data.get("relation") in ("USES", "DEPENDS_ON"):
                downstream.add(tgt)
            if tgt == svc and data.get("relation") in ("USES", "DEPENDS_ON"):
                downstream.add(src)

    return {
        "direct": direct,
        "downstream": list(downstream),
        "total_impact": len(direct) + len(downstream)
    }


def get_policies_for_event(graph, event_name):
    """What compliance policies govern this event?"""
    policies = []
    for src, tgt, data in graph.G.edges(data=True):
        if data.get("relation") == "GOVERNS" and tgt == event_name:
            policies.append(src)
    return policies


def get_user_devices(graph, user):
    """What devices does this user use?"""
    devices = []
    for src, tgt, data in graph.G.edges(data=True):
        if src == user and data.get("relation") == "USES":
            # Check if the target node is a Device entity
            node_data = graph.G.nodes.get(tgt, {})
            entity = node_data.get("entity")
            if entity and type(entity).__name__ == "Device":
                devices.append(tgt)
    return devices

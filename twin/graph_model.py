import networkx as nx

class EnterpriseGraph:
    def __init__(self):
        self.G = nx.DiGraph()

    def add_node(self, entity):
        critical_systems = {"CustomerDB", "API-Gateway", "Deployment-Service", "Kubernetes", "AWS"}
        is_critical = entity.name in critical_systems or type(entity).__name__ == "Database"
        crit_val = "High" if is_critical else "Medium"
        self.G.add_node(entity.name, entity=entity, criticality=crit_val)

    def add_edge(self, source, target, relation):
        self.G.add_edge(source, target, relation=relation)

    def summary(self):
        return {
            "nodes": self.G.number_of_nodes(),
            "edges": self.G.number_of_edges()
        }

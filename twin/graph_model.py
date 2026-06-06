import networkx as nx

class EnterpriseGraph:
    def __init__(self):
        self.G = nx.DiGraph()

    def add_node(self, entity):
        self.G.add_node(entity.name, entity=entity)

    def add_edge(self, source, target, relation):
        self.G.add_edge(source, target, relation=relation)

    def summary(self):
        return {
            "nodes": self.G.number_of_nodes(),
            "edges": self.G.number_of_edges()
        }

# Architectural Documentation Index

This directory contains the detailed architectural specifications, agent profiles, protocol definitions, and incident simulation guides for the Enterprise Council AI platform.

---

## Documentation Registry

| Document | Primary Focus | Key Topics Covered |
|---|---|---|
| [Digital Twin & MCP Tools](digital_twin.md) | Graph Topology & Protocol Layer | NetworkX graph building, DiGraph entities, edge relationships, and the 14 standard Splunk MCP tools. |
| [Agent Profiles & Consensus](agents.md) | Agent Design & Decision Logic | Security, Infrastructure, Compliance, Business, and Council agent prompts, dynamic tools, and consensus formulas. |
| [Demo Scenario & Debate](demo_scenario.md) | Simulation & Operational Flow | John Carter VPN incident timeline, agent assessments, 3-round debate transcript, and automated SOAR responses. |
| [Hackathon Strategy](hackathon.md) | Project Strategy & Vision | Hackathon requirements analysis, track selection rationale, unique value proposition, and ultimate project vision. |

---

## Architectural Diagrams and Assets

The following visual aids are stored in the repository root and referenced here to support the documentation:

* **Architecture Diagram** (`../architecture_diagram.png`): High-level system architecture illustrating the flow of data from Splunk Enterprise through the MCP Server and Digital Twin to the Agent Debate Engine.
* **Authentication Gateway** (`auth_gateway.png`): User interface layout showing the federated identity selection screen.
* **Operational Dashboard** (`dashboard_layout.png`): Console command center showing the live 5-panel layout, including the Digital Twin visualizer, agent opinions list, and debate transcript pane.
* **Public Landing Page** (`landing_page.png`): Desktop layout of the marketing portal detailing the core problem, solution, and multi-agent debate features.

# Digital Twin and Model Context Protocol Integration

The Digital Twin is the central operational model of Enterprise Council AI. By representing organizational telemetry, infrastructure assets, user identities, and compliance policies as an active relationship graph, the system moves beyond isolated log search results to construct a living semantic map of the enterprise.

---

## NetworkX Graph Generation

The Digital Twin is built on a directed relationship graph using the Python NetworkX library (`networkx.DiGraph`). Instead of querying logs as flat text tables, the system models each element as an entity (node) connected by specific security or operational relationships (edges).

### Graph Entities (Nodes)
The topology supports seven distinct entity classes, each representing a logical layer of the enterprise:

* **User**: Human operators and administrative identities (e.g., John, Alice, Bob).
* **Department**: Business units within the company (e.g., Engineering, Operations, Security).
* **Device**: Endpoint systems and developer workstations (e.g., MacBook-Pro-01).
* **Service**: Infrastructure applications and platforms (e.g., VPN, Kubernetes, AWS, GitHub, API-Gateway).
* **Database**: Persistent storage systems containing corporate records (e.g., CustomerDB).
* **Alert**: Real-time anomalies detected by security or system monitoring tools (e.g., Privilege Escalation).
* **Policy**: Regulatory rules and internal guidelines (e.g., GDPR Article 32, PCI-DSS Requirement 10).

### Edge Relationships
Connections between nodes define access rights, accountability paths, and impact scopes:

| Source Node | Relationship | Target Node | Operational Description |
|---|---|---|---|
| User | BELONGS_TO | Department | Mapped from business files to establish organizational alignment. |
| User | USES | Device | Identifies endpoints used by specific employees. |
| User | ACCESSES | Service | Identifies cloud or internal system access profiles. |
| Alert | TARGETS | User | Indicates security alerts triggered by user activities. |
| Alert | AFFECTS | Service | Tracks infrastructure anomalies impacting live services. |
| Policy | GOVERNS | Alert | Maps regulatory standards to specific alert scenarios. |
| Service | USES | Database | Connects application dependencies to database engines. |

### Graph Context Initialization
The Digital Twin synchronizes data directly from mock CSV datasets (simulating Splunk indexes) or live Splunk searches:
1. **Business Synchronization**: Populates `User` and `Department` nodes and links them via `BELONGS_TO` edges.
2. **Security Telemetry**: Populates `Device` and `Alert` nodes and links them via `USES` and `TARGETS` edges.
3. **Infrastructure Monitoring**: Detects services and databases, linking them via `AFFECTS` edges.
4. **Compliance Policies**: Discovers active policy definitions and maps them via `GOVERNS` edges.
5. **Static Backbone**: Automatically connects critical baseline infrastructure dependencies (e.g., AWS, Kubernetes, CustomerDB, API-Gateway, and VPN) to model escalation flows.

---

## Splunk Model Context Protocol (MCP) Tools

Agents query Splunk indexes and the Digital Twin in real-time utilizing standard Model Context Protocol (MCP) schemas. The MCP server registers 14 core tools divided into native Splunk operations, system discovery metrics, and Splunk AI Assistant (SAIA) services.

### Core Splunk Operations

#### 1. splunk_run_query
* **Description**: Executes arbitrary Search Processing Language (SPL) queries to fetch security logs, infrastructure events, or transaction records.
* **Input Parameters**:
  * `query` (string, required): The SPL query to run.
  * `max_results` (integer, optional): Limits the returned events (default: 50).
* **Return Format**: A JSON structure containing the query string, execution duration, total count, and an array of raw event dictionaries.

#### 2. splunk_get_info
* **Description**: Connects to the Splunk management endpoint to fetch general system health, software version, build numbers, and architecture properties.
* **Input Parameters**: None.
* **Return Format**: System attributes including version (e.g., 9.2.1), OS properties (e.g., Linux), server name, and hardware configuration.

#### 3. splunk_get_indexes
* **Description**: Lists all active data indexes configured on the Splunk indexer cluster.
* **Input Parameters**: None.
* **Return Format**: An array of index definitions listing event counts and operational status (enabled/disabled).

#### 4. splunk_get_index_info
* **Description**: Pulls diagnostic parameters, storage caps, and current volume metrics for a specific index.
* **Input Parameters**:
  * `index` (string, required): The index name to inspect (e.g., security).
* **Return Format**: Detailed metrics including current disk footprint in megabytes, max capacity settings, and event statistics.

#### 5. splunk_get_metadata
* **Description**: Returns index summary metadata detailing active hosts, log sources, and sourcetype tags to help agents discover valid search boundaries.
* **Input Parameters**:
  * `index` (string, optional): Filters metadata to a target index.
* **Return Format**: Arrays of unique hosts, source logs, and sourcetypes registered in the target index.

---

### Identity and Knowledge Objects

#### 6. splunk_get_user_info
* **Description**: Returns identity information, security roles, real names, and contact details for a specific user.
* **Input Parameters**:
  * `username` (string, required): The login ID of the user.
* **Return Format**: Identity mappings detailing assigned roles (e.g., developer, admin), email addresses, and default application domains.

#### 7. splunk_get_user_list
* **Description**: Returns all user accounts configured on the platform along with locking statuses and security settings.
* **Input Parameters**: None.
* **Return Format**: An array of user profiles detailing lock status, directory membership, and security permissions.

#### 8. splunk_get_kv_store_collections
* **Description**: Lists configurations, data counts, and size metrics for all KV Store collections.
* **Input Parameters**: None.
* **Return Format**: An array of collection properties detailing storage sizes and record counts.

#### 9. splunk_get_knowledge_objects
* **Description**: Retrieves configured saved searches, alerts, lookups, macros, and data models.
* **Input Parameters**:
  * `type` (string, optional): Filters objects by type (e.g., alert, savedsearch).
* **Return Format**: An array of configured query targets, their raw search expressions, and schedules.

#### 10. splunk_run_saved_search
* **Description**: Dispatches and runs an existing preconfigured Splunk saved search or correlation rule.
* **Input Parameters**:
  * `name` (string, required): The name of the saved search to run.
* **Return Format**: Job dispatch state, execution progress identifiers, and event lists.

---

### Splunk AI Assistant (SAIA) Tools

#### 11. saia_generate_spl
* **Description**: Generates syntax-compliant SPL search statements from natural language descriptions.
* **Input Parameters**:
  * `question` (string, required): Plain English request (e.g., "Show me all failed logins from John yesterday").
  * `context` (object, optional): Incident context parameters to help focus the SPL logic.
* **Return Format**: The generated SPL command string and optimization suggestions.

#### 12. saia_explain_spl
* **Description**: Translates complex SPL statements into plain English explanations.
* **Input Parameters**:
  * `query` (string, required): The SPL query to analyze.
* **Return Format**: A step-by-step text breakdown of what index is searched, what fields are filtered, and how results are aggregated.

#### 13. saia_optimize_spl
* **Description**: Identifies performance issues in SPL queries and returns optimized search alternatives.
* **Input Parameters**:
  * `query` (string, required): The SPL query to optimize.
* **Return Format**: An optimized SPL query string alongside lists of specific optimizations made (e.g., moving search filters before commands).

#### 14. saia_ask_splunk_question
* **Description**: General assistant tool answering conceptual questions about Splunk commands, configurations, and best practices.
* **Input Parameters**:
  * `question` (string, required): Conceptual question (e.g., "What is the difference between transaction and stats?").
* **Return Format**: A text explanation with code examples.

---

## Agentic Runtime Extensions

During the debate, agents register custom tools dynamically to investigate specific indicators of compromise:

* **Security Agent**: Registers `get_threat_intel` to query threat feeds, return malicious IP lists, and match indicators against feeds.
* **Infrastructure Agent**: Registers `get_service_metrics` to pull CPU usage, connection spikes, and memory footprint.
* **Compliance Agent**: Registers `check_policy_violations` and `get_audit_trail` to run integrity checks on log files and map violations to compliance targets.
* **Business Agent**: Registers `get_user_criticality` and `assess_revenue_impact` to assess SLA penalties and revenue at risk before restricting permissions.

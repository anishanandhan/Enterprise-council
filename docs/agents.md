# Agent Profiles, Prompts, and Consensus Framework

Enterprise Council AI implements a multi-agent decision intelligence console where specialized agents represent distinct departments in a simulated organization. Together, they evaluate cybersecurity incidents by balancing system security, business operations, regulatory compliance, and infrastructure availability.

---

## Agent Architecture Overview

Each agent is modeled as an autonomous loop capable of gathering data from the Digital Twin topology, calling Splunk MCP tools, and analyzing telemetry under a customized system prompt.

```
                  Incident Telemetry
                          │
                          ▼
           ┌──────────────┴──────────────┐
           ▼                             ▼
   Digital Twin Context          Splunk MCP Tools
           │                             │
           └──────────────┬──────────────┘
                          ▼
             Agent Loop (Reasoning Engine)
                          │
                          ▼
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
       Risk Level    Confidence     Reasoning Log
```

---

## Agent Profiles

### 1. Security Agent
* **Domain Focus**: Minimizes security exposure, blocks threats, stops malicious actions, and evaluates MITRE ATT&CK technique maps.
* **System Prompt**:
  ```
  You are the Security Agent in an Enterprise AI Council. Your mission is to protect the company from threats. You run an agentic loop investigating security events using Splunk tools before arriving at a final assessment.
  ```
* **Decision Questions**:
  * Is this activity an active attack or a credential theft?
  * What is the threat actor's capability and severity?
  * What is the recommended MITRE ATT&CK mitigation tactic?
* **Dynamic Tools**:
  * `get_threat_intel`: Queries threat intelligence feeds for malicious reputation data.
* **Analysis Outputs**:
  * Risk level estimation.
  * MITRE ATT&CK technique mapping.
  * Security-focused containment recommendation.

### 2. Infrastructure Agent
* **Domain Focus**: Maintains service availability, minimizes the blast radius of containment actions, and protects service uptime.
* **System Prompt**:
  ```
  You are the Infrastructure Agent in an Enterprise AI Council. Your mission is to maintain service reliability and uptime. You run an agentic loop to forecast resource usage and assess service reliability using Splunk Deep Time Series tools before arriving at a final assessment.
  ```
* **Decision Questions**:
  * Will blocking this user break operational systems (e.g., deployments)?
  * What downstream services are dependent on the targeted systems?
  * What is the impact of shutting down service endpoints?
* **Dynamic Tools**:
  * `get_service_metrics`: Queries real-time CPU utilization, active connections, and memory parameters.
* **Analysis Outputs**:
  * Blast radius calculation.
  * Service dependency impact metrics.
  * Availability-driven mitigation suggestions.

### 3. Compliance Agent
* **Domain Focus**: Ensures regulatory compliance (GDPR, PCI-DSS, EU AI Act), policies enforcement, and proper evidence preservation.
* **System Prompt**:
  ```
  You are the Compliance Agent in an Enterprise AI Council. Your mission is to ensure regulatory compliance and proper governance. You run an agentic loop checking policies and verifying audit logs using Splunk tools before arriving at a final assessment.
  ```
* **Decision Questions**:
  * Does this event trigger external reporting obligations (e.g., GDPR data breach)?
  * Are we preserving log trails according to retention policies?
  * What policies govern the affected data stores?
* **Dynamic Tools**:
  * `check_policy_violations`: Reviews activities against industry and corporate regulations.
  * `get_audit_trail`: Verifies log file cryptographic SHA-256 hashes and sets preservation retention.
* **Analysis Outputs**:
  * Policy violation catalog.
  * Log chain of custody validation status.
  * Compliance-driven mitigation requirements.

### 4. Business Agent
* **Domain Focus**: Limits business disruption, calculates revenue at risk, and protects critical customer contracts.
* **System Prompt**:
  ```
  You are the Business Agent in an Enterprise AI Council. Your mission is to minimize business disruption and protect revenue. You run an agentic loop checking business criticality and revenue impact using Splunk tools before arriving at a final assessment.
  ```
* **Decision Questions**:
  * What is the revenue at risk if we block this user or service?
  * Are there SLA penalties associated with containment?
  * How critical is this user's role to general operations?
* **Dynamic Tools**:
  * `get_user_criticality`: Retrieves organizational tiers and responsibilities.
  * `assess_revenue_impact`: Calculates SLA penalties and operational cost estimates.
* **Analysis Outputs**:
  * Role criticality assessment.
  * Financial cost projections.
  * Business-driven containment suggestions.

### 5. Council Agent (Consensus Aggregator)
* **Domain Focus**: Collects agent opinions and coordinates debates to synthesize a unified recommended action.
* **System Prompt**:
  ```
  You are the Council Agent in an Enterprise AI Council. Your role is to synthesize multiple expert perspectives and simulation data into a balanced, evidence-based decision.
  ```
* **Deliberation Process**:
  1. Gathers opinions from Security, Infrastructure, Compliance, and Business agents.
  2. Executes impact simulation workflows forecasting containment risks.
  3. Synthesizes competing opinions and logs the final consensus report.

---

## Consensus Calculation Framework

The Council Agent evaluates agent recommendations using a weighted voting system based on evaluated risk levels and agent confidence scores.

### 1. Risk Level Weights
Each agent evaluates the incident risk level, which translates to a specific priority weight:

| Risk Level | Numeric Weight ($W_{risk}$) | Description |
|---|---|---|
| Critical | 1.00 | Demands immediate action. |
| High | 0.75 | Requires urgent intervention. |
| Medium | 0.50 | Moderated impact. |
| Low | 0.25 | Standard alert status. |

### 2. Opinion Score Calculation
An agent's opinion score ($S_{opinion}$) is calculated by multiplying its risk weight by its confidence value ($C_{agent}$, ranging from 0.0 to 1.0):

$$S_{opinion} = W_{risk} \times C_{agent}$$

*Example: If the Security Agent reports a **High** risk ($W_{risk} = 0.75$) with a confidence of **0.90**, its score is:*

$$S_{opinion} = 0.75 \times 0.90 = 0.675$$

### 3. Consensus Decision Rules
* **Without Simulation**: The Council Agent calculates the average score of all agent votes. It outputs:
  * **Temporary Restriction** if overall risk is Critical.
  * **Restricted Access** if overall risk is High.
  * **Continued Monitoring** if overall risk is Medium or Low.
  * Consensus Confidence is scaled as:
    $$C_{council} = 0.85 + (S_{average} \times 0.10)$$
* **With Simulation**: The Council Agent evaluates the output of the Impact Simulation Engine. It recommends the action that minimizes overall risk. The confidence score is calculated by subtracting the recommended action's total risk footprint from 95%:
    $$C_{council} = 0.95 - \left(\frac{R_{total}}{300}\right) \times 0.15$$
    *(where $R_{total}$ is the sum of security, business, and compliance risk percentages, bounded between 0 and 300)*
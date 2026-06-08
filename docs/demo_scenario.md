# Incident Simulation and Debate Walkthrough

This document details the incident simulation scenario involving John Carter at NovaTech Solutions. It walks through the chronological timeline of events, describes how each agent evaluates the data, and explains the multi-round agentic debate leading to the final consensus recommendation.

---

## Organizational Context

* **Company**: NovaTech Solutions
* **Target Subject**: John Carter
* **Role**: Lead DevOps Engineer
* **Business Criticality**: Very High
* **Assigned Department**: Engineering
* **Access Level**: Production Administrator (AWS, Kubernetes, VPN, CustomerDB, API-Gateway)

---

## The Incident Timeline

The simulation models an escalation sequence spanning a 30-minute window. Each event is logged in the simulated Splunk indexes (`security`, `infrastructure`, `compliance`, `business`):

```
 09:00            09:15            09:20                 09:25               09:27              09:30
  │                │                │                     │                   │                  │
  ▼                ▼                ▼                     ▼                   ▼                  ▼
VPN Login ───► 20GB Download ───► Privilege ───────► Production Deploy ───► Sensitive File ───► Council
(Anomalous IP)                  Escalation (UAC)    (Kubernetes API)        Copy (CustomerDB)   Triggered
```

### Event Breakdown

* **09:00 - VPN Login Anomaly**:
  * **Log Source**: `WinEventLog:Security` (index = `security`)
  * **Telemetry**: User `John` authenticates via VPN from an IP address block not matching his standard home profile.
* **09:15 - Large Data Download**:
  * **Log Source**: `syslog` (index = `security`)
  * **Telemetry**: Endpoint logs record a bulk transfer of 20GB of data from internal repositories within a 3-minute window.
* **09:20 - Privilege Escalation**:
  * **Log Source**: `WinEventLog:Security` (index = `security`)
  * **Telemetry**: User executes a bypass on User Account Control (UAC) mechanisms, elevating session rights to local System Admin.
* **09:25 - Production Deployment Alert**:
  * **Log Source**: `opentelemetry` (index = `infrastructure`)
  * **Telemetry**: A deployment script is dispatched directly to the active Kubernetes production cluster, modifying the core `API-Gateway` parameters.
* **09:27 - Sensitive File Copy**:
  * **Log Source**: `business_app_audit` (index = `compliance`)
  * **Telemetry**: Audit events record a read-and-copy operation targeting customer records in the primary `CustomerDB`.
* **09:30 - Security Console Alert**:
  * **Status**: Critical security alert is flagged, triggering the Enterprise Council multi-agent evaluation.

---

## Agent Evaluations

When the council is convened, each agent queries the Digital Twin and Splunk logs, evaluating the events from its perspective:

### 1. Security Agent Assessment
* **Evaluation**: The sequence represents a classic lateral movement and data exfiltration flow. The combination of an anomalous login, privilege escalation, and massive downloads indicates credential compromise.
* **Recommendation**: Immediate **Block** on John Carter's accounts.
* **Reasoning**: To prevent further system tampering or data leakage, we must lock out the identity immediately. Delaying containment increases threat exposure.

### 2. Infrastructure Agent Assessment
* **Evaluation**: John Carter is currently pushing a production update to the `API-Gateway` and the database connectors.
* **Recommendation**: **Restrict** permissions instead of a complete Block.
* **Reasoning**: Blocking John during an active Kubernetes deployment will orphan the deployment process, resulting in database transaction lockups and causing a complete outage on the Web Portal.

### 3. Compliance Agent Assessment
* **Evaluation**: The data copied from `CustomerDB` falls under GDPR and PCI-DSS compliance boundaries. The UAC bypass represents an internal policy violation.
* **Recommendation**: **Restrict** access + lock down audit logs.
* **Reasoning**: While containment is necessary to meet GDPR breach mitigation constraints, we must avoid terminating active sessions abruptly if it corrupts forensic logs. We must immediately generate a tamper-proof SHA-256 validation hash of the audit trail to protect evidence.

### 4. Business Agent Assessment
* **Evaluation**: John Carter is the designated Lead DevOps Engineer for NovaTech Solutions.
* **Recommendation**: **Monitor** or **Restrict** access.
* **Reasoning**: Fully blocking John's accounts stops all engineering operations, violating service SLAs and costing the company an estimated $50,000 in immediate business delays and SLA penalties.

---

## The Debate Transcript

The system orchestrates a 3-round debate sequence to reconcile these competing recommendations:

### Round 1: Opening Positions
* **Security Agent**: "The telemetry shows a critical privilege escalation and exfiltration pattern. I recommend blocking John Carter's Okta profile immediately to secure the system."
* **Infrastructure Agent**: "I object to a complete block. John is managing a live deployment to the API-Gateway. An immediate lockout will cause a service outage affecting thousands of customers."
* **Compliance Agent**: "We have PCI-DSS and GDPR data scope at risk here. Containment is required, but we must protect log integrity first. I need the audit trail secured before any system lockout."
* **Business Agent**: "A complete lockout of John Carter disrupts engineering operations, costing us $50,000 in direct revenue risks and SLA penalties. We should restrict access to sensitive segments rather than a total block."

### Round 2: Cross-Examination
* **Security Agent**: "Infrastructure and Business are neglecting the security threat. If this is a ransomware actor, the financial and operational impact of an enterprise-wide infection will far exceed a $50,000 SLA penalty."
* **Infrastructure Agent**: "We can block direct writes to `CustomerDB` while keeping John's Kubernetes session active under read-only restrictions. This keeps systems online while limiting the write blast radius."
* **Compliance Agent**: "I agree with Infrastructure's compromise. Restricting database access satisfies containment mandates, and keeping the session alive under read-only monitoring preserves the forensic audit chain of custody."
* **Business Agent**: "Read-only access limits our SLA exposure. We can verify John's identity through secondary out-of-band channels while he remains under restriction."

### Round 3: Synthesis and Consensus
* **Council Agent**: "After reviewing all arguments and running the impact simulator, the Council rejects the extreme options of a total Block or simple Monitoring.
  
  The Council adopts a **Restrict Access** action:
  1. Revoke John Carter's write permissions to `CustomerDB` and the production deployment tools.
  2. Maintain his login state in a restricted read-only mode to prevent script corruption and preserve the live log audit trail.
  3. Dispatch an automated Slack challenge requesting immediate identity verification.
  
  This balanced containment achieves security goals while preventing a major operational outage."

---

## Automated Incident Response (SOAR)

Once consensus is established, the platform dispatches execution payloads to integrated security orchestration tools:

1. **Okta**: Suspends write credentials, forcing active tokens to a read-only role.
2. **Cortex XSOAR / ServiceNow**: Opens a security incident ticket containing the debate transcript and decision audit.
3. **Slack**: Sends a confirmation message to the Security Operations channel detailing the restriction and provides quick-action buttons for manual analyst overrides.
4. **Tines**: Triggers a playbook to monitor subsequent connections from John Carter's endpoint.

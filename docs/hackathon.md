What The Hackathon Wants

Most people think:

Use AI
+
Use Splunk

No.

The hackathon specifically mentions:

AI Agents
MCP Server
Hosted Models
AI Assistant
Agentic Workflows

They want:

AI systems that think and operate using Splunk data.
PART 6: What Most Teams Will Build

Most teams will create:

ChatGPT for Splunk

Example:

User asks:

Show failed logins

AI answers:

There were 15 failed logins.

Cool.

But not unique.

PART 7: Why We Rejected That

We wanted something judges remember.

Not:

AI Search Tool

Not:

AI Dashboard

Not:

AI Chatbot

We wanted:

A completely new way
of making enterprise decisions
PART 8: Our Core Idea

Imagine an organization.

When something serious happens:

Who decides?

Not one person.

Multiple teams.

Security Team

asks:

Is this dangerous?

Infrastructure Team

asks:

Will systems fail?

Compliance Team

asks:

Are regulations affected?

Business Team

asks:

Will revenue be affected?

Management

asks:

What should we do?

Real organizations work through discussion.

We thought:

Why not recreate that using AI?
PART 9: Enterprise Council AI

This became our project.

Instead of:

One AI Agent

We build:

An AI Council

Multiple agents.

Each agent behaves like a different department.

PART 10: Track Selection

Hackathon Tracks:

Observability

Understand system health.

Security

Threat detection.

Platform & Developer Experience

Build new ways to interact with Splunk.

We chose:

Platform & Developer Experience

Because we are not building:

A security product

We are building:

An AI Operating System
for enterprise decisions.
PART 11: Digital Twin

This is the most important concept.

What is a Digital Twin?

A virtual representation of reality.

Example:

Real World:

John
Laptop
VPN
Database
AWS

Digital Twin:

John
 │
 ├── Laptop
 │
 ├── VPN
 │
 ├── AWS
 │
 └── Database

Now AI understands relationships.

Not just logs.

PART 12: Why Digital Twin Matters

Without Twin:

John downloaded file.

AI only sees:

One event.

With Twin:

AI sees:

John

Lead DevOps Engineer

Has AWS access

Has production access

Uses critical systems

Huge difference.

PART 13: Our Agents

We designed five agents.

Security Agent

Goal:

Reduce risk.

Questions:

Is this an attack?

How severe is it?
Infrastructure Agent

Goal:

Keep systems running.

Questions:

Will services fail?

Will uptime be affected?
Compliance Agent

Goal:

Follow regulations.

Questions:

Should evidence be preserved?

Are policies violated?
Business Agent

Goal:

Protect business operations.

Questions:

Will revenue be affected?

Will customers suffer?
Council Agent

Goal:

Listen to all agents.

Create final decision.
PART 14: Demo Scenario

We created:

Company

NovaTech Solutions

Departments:

Engineering
Security
Finance
Operations

Employee:

John Carter

Role:

Lead DevOps Engineer

Criticality:

Very High

Incident:

09:00

VPN Login

09:15

20GB Download

09:20

Privilege Escalation

09:25

Production Deployment

09:27

Sensitive File Copy

09:30

Critical Alert

Now every agent has something to care about.

PART 15: Agent Debate

Security Agent:

Block John immediately.

Business Agent:

He's the deployment lead.

Infrastructure Agent:

Blocking him may break production.

Compliance Agent:

Preserve evidence first.

Council Agent:

Temporary restriction.

Preserve evidence.

Increase monitoring.

Escalate investigation.

This debate is the heart of the project.

PART 16: Splunk Architecture

We created four indexes.

security

Stores:

VPN Logins
Downloads
Privilege Escalation
Threats
infrastructure

Stores:

CPU
Database Events
Deployments
System Health
business

Stores:

Employee Roles
Departments
Criticality
compliance

Stores:

Policies
Audit Events
Violations
PART 17: Datasets

Created:

security_logs.csv
infra_logs.csv
business_logs.csv
compliance_logs.csv

These simulate enterprise data.

PART 18: Repository Structure

Current vision:

enterprise-council-ai/

docs/
datasets/

twin/
agents/
orchestrator/
splunk/
simulation/
frontend/
PART 19: Digital Twin Builder

First real software component.

Input:

CSV Files

Output:

Graph

Example:

John
 │
 ├── Uses → MacBook
 │
 ├── Accesses → AWS
 │
 ├── Accesses → CustomerDB
 │
 └── Generates → Alert

Using:

Python
+
NetworkX
PART 20: Why This Is Different

Most hackathon projects:

User
↓
AI
↓
Answer

Our system:

Splunk Data
↓
Digital Twin
↓
Agent Council
↓
Debate
↓
Consensus
↓
Impact Prediction
↓
Decision

This is much closer to how real organizations operate.

PART 21: Bonus Prizes We Target
Best Use of MCP Server

Because agents will query Splunk through MCP.

Best Use of Hosted Models

Because agents can use Splunk-hosted AI models.

Best Use of Developer Tools

Because we're building a complete platform.

PART 22: What Judges Will See

In 3 minutes:

Screen 1

Incident appears.

Screen 2

Digital Twin graph lights up.

Screen 3

Agents start debating.

Security:

Block immediately.

Business:

Too risky.

Compliance:

Preserve evidence.

Infrastructure:

Check deployment impact.
Screen 4

Consensus appears.

Recommended Action

Restrict privileges
Preserve evidence
Continue monitoring
Escalate analyst review

Confidence: 89%
PART 23: Ultimate Vision

We are not building:

AI for Splunk

We are building:

An AI Executive Council
for enterprise operations

A system that takes operational data from Splunk, builds a living Digital Twin of the organization, allows specialized AI agents to reason from different perspectives, debate possible actions, predict consequences, and generate consensus-driven recommendations for enterprise decision making.

That is the complete vision, architecture, workflow, strategy, judging alignment, demo story, and technical roadmap of everything we've discussed so far.
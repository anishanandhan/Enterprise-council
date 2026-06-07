# 🛡️ Enterprise Council AI
> Splunk Data ➔ Digital Twin ➔ AI Council Debate ➔ Impact Simulation ➔ Consensus Decision Intelligence

[![GitHub License](https://img.shields.io/github/license/anishanandhan/Enterprise-council?style=flat-square&color=emerald)](LICENSE)
[![Streamlit App](https://img.shields.io/badge/Streamlit-App-red?style=flat-square&logo=streamlit)](https://enterprise-council-ai.web.app)
[![API docs](https://img.shields.io/badge/FastAPI-Docs-blue?style=flat-square&logo=fastapi)](http://localhost:8001/docs)

Enterprise Council AI is a multi-agent decision intelligence system. It translates raw Splunk security logs into a living graph-based digital twin of your network, spins up specialized AI agents (Security, Infrastructure, Compliance, Business) to represent different business priorities, and hosts an autonomous, multi-round debate to recommend containing threats without taking critical servers offline.

---

## 💡 Inspiration
We've all been there: a critical security alert fires at 2:00 AM. 
```
02:15 AM - Critical Privilege Escalation Detected: John (Lead DevOps)
```
The immediate instinct of the SOC analyst is to quarantine the account. But John is currently deploying a hotfix to the payment gateway. If you disable his credentials, the release fails, transactions fail, and the business loses thousands of dollars per minute. 

Security wants containment. Infrastructure wants uptime. Compliance wants to preserve evidence. Business wants revenue. 

Usually, this ends up in a frantic phone call between tired managers trying to balance risk. We built Enterprise Council AI to automate this decision process, assembling a digital council of domain-specific agents to debate risk and recommend balanced containment strategies in seconds.

---

## ⚙️ What it does
* **Translates Logs to a Digital Twin:** Ingests Splunk event indices and builds a topological relationship graph (using NetworkX) linking users, endpoints, credentials, databases, and compliance frameworks.
* **Assembles a Dynamic Council:** Depending on the classification of the incident, it calls up relevant agents. An database outlier spike calls Security and Business; a database outage calls Infrastructure and Business.
* **Runs Multi-Round Debates:** Domain agents represent distinct viewpoints (Security wants to block, Business wants to keep online). They issue opening stances, cross-examine other agents, and query Splunk for evidence.
* **Simulates Blast Radius and Risks:** Calculates total operational risk percentages (Security vs. Business vs. Compliance) across multiple containment strategies (Block User, Monitor Only, Restrict Access).
* **Consensus-Driven Resolution:** Synthesizes the debate history and risk simulation into a single recommendation with a confidence percentage, secured with a cryptographic hash.
* **SOAR Integrations:** Includes one-click playbooks to trigger Okta user suspensions, Palo Alto Cortex XSOAR events, Slack notifications, Tines workflows, and ServiceNow tickets.

---

## 🛠️ Tech Stack & Shields
* **Logic/Core:** Python 3.11, NetworkX (Graph Modeling), Pandas, Matplotlib (Topology visualization)
* **Web UI:** React (Public Landing Page), Streamlit (SecOps Command Center)
* **Backend:** FastAPI (REST API + SDK integration), SlowAPI (Rate limiting)
* **Deployment:** Firebase Hosting (Static frontend), Uvicorn (Local API runtime)
* **Security Telemetry:** Splunk Enterprise (Native Python SDK `splunklib` + Custom MCP tools)

---

## 🧠 How we built it
We chose **Streamlit** for the Operational Command Center because it lets us compile complex data structures, graph plots, and tables into a clean layout quickly. The landing page is built in **React** (loaded dynamically with Framer Motion and Tailwind) to provide a premium feel for judges. 

The heart of the application is the **Model Context Protocol (MCP)**. Instead of hardcoding API search scripts, we exposed Splunk indexes as MCP resources. Agents can autonomously call 14 native tools (`splunk_run_query`, `saia_generate_spl`, etc.) to gather context, extract logs, and argue their positions using evidence.

---

## 💥 Challenges (Venting at 3 AM)
Building this was a series of battles against compilation timings and asynchronous dependencies. 

1. **The Streamlit Column NameError Nightmare:**
   We decided to restructure the UI to drop the sidebar container entirely and use a horizontal top navigation bar. This meant placing the active incident queue and parameters in a left column (`col_left`) and the outputs in a right column (`col_right`). 
   Because Streamlit runs top-to-bottom, referencing the `run_button` result further down to execute the debate pipeline triggered a series of global `NameError` exceptions during rendering cycles. We spent two hours tracing scope errors before encapsulating the entire execution code path and checklist render callbacks directly inside the columns' layout scope.

2. **The Splunk Connection Wall:**
   We wanted the app to connect to a live Splunk instance. But when judges or developers run the repo offline, the app shouldn't crash. We had to build a robust, dynamic client wrapper that checks for a live Splunk server, and if it fails to connect, automatically shifts into a mock CSV fallback mode. The fallback mirrors index shapes perfectly so that no agent workflows break.

3. **Matplotlib Thread Locking:**
   Generating the NetworkX topology graph image on every single Streamlit reload cycle was blocking FPDF from generating the downloadable incident report PDF. The Matplotlib rendering threads were fighting over resources. We fixed this by forcing the non-interactive `Agg` backend globally at the top of the file:
   ```python
   import matplotlib
   matplotlib.use("Agg")
   ```

---

## 🏆 Accomplishments
* We got 4 distinct LLM agent prompts to debate and modify their stances based on simulated data inputs.
* The transition between the static React landing page, the credentials access gateway, and the horizontal command center dashboard feels fast and clean.
* The generated PDF contains a cryptographic SHA-256 integrity hash representing the exact state of the council's decision.

---

## 📖 What we learned
We learned that exposing database queries as tools (via MCP) is far more powerful than parsing logs. Giving LLMs the ability to generate and execute their own SPL queries makes them incredibly adaptable to changing event formats.

---

## 🔮 What's next
1. **Active Active-Directory Sync:** Moving from simulated Okta blocks to live domain controller directory policy pushes.
2. **LLM Debate Benchmarking:** Running synthetic incident inputs through different models (Gemini, Claude, Llama) to compare consensus quality.
3. **Graph Neural Networks (GNN):** Training an node classification model directly on the Digital Twin graph to predict lateral movement vectors.

---

## 🚀 Setup & Installation

### Prerequisites
* Python 3.10+
* Node.js (Optional, only for running landing page locally)
* (Optional) Gemini API Key

### 1. Clone & Environment Setup
```bash
git clone https://github.com/anishanandhan/Enterprise-council.git
cd Enterprise-council

# Initialize virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Create a `.env` file in the root directory:
```env
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your_secure_password
GEMINI_API_KEY=your_gemini_api_key
```
*Note: If no env file is provided, the application automatically defaults to local offline datasets and fallback templates.*

### 3. Running the App

**Start the developer REST API (FastAPI):**
```bash
venv/bin/uvicorn api.main:app --port 8001 --reload
```

**Start the static HTTP server (Landing Page):**
```bash
python3 -m http.server 8080
```

**Start the Operational Command Center (Streamlit):**
```bash
streamlit run frontend/app.py
```
Open `http://localhost:8502` to enter the gateway.

---

## 👥 Team
* **Anish** — Lead AI Engineer & Infrastructure Integration. Built the multi-agent debate loop, Splunk MCP wrappers, and the Digital Twin modeling.

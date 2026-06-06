"""
agentic_tools.py — Splunk AI for Apps Agentic Tool Executor

Provides agents with an autonomous tool-calling interface for
investigating incidents through Splunk data.

    Agent Prompt
        ↓
    Plan (which tools to call)
        ↓
    Execute (run SPL / graph query / AI inference)
        ↓
    Observe (interpret results)
        ↓
    Decide (next action or final answer)

This is the "AI for Splunk Apps" integration — making agents
behave as first-class Splunk App entities that autonomously
query and reason over enterprise data.
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class AgenticTool:
    """Definition of a callable tool an agent can use."""

    def __init__(self, name, description, handler, category="general"):
        self.name = name
        self.description = description
        self.handler = handler
        self.category = category

    def to_schema(self):
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category
        }


class AgenticToolExecutor:
    """
    Gives agents the ability to autonomously call tools.

    Each agent gets an executor instance with registered tools.
    The agent can plan, execute, observe, and decide in a loop.
    """

    def __init__(self, agent_name):
        self.agent_name = agent_name
        self._tools = {}
        self._execution_log = []
        self._register_default_tools()

    def _register_default_tools(self):
        """Register the standard set of tools available to all agents."""

        # Tool 1: Run SPL search
        def run_spl(args):
            from splunk.splunk_client import get_client
            client = get_client()
            spl = args.get("spl", "index=security | head 5")
            max_results = args.get("max_results", 20)
            results = client.search(spl, max_results=max_results)
            return {
                "query": spl,
                "result_count": len(results),
                "results": results[:10]  # Cap at 10 for context window
            }

        self.register(AgenticTool(
            name="run_spl_search",
            description="Execute an SPL query against Splunk and return results",
            handler=run_spl,
            category="splunk"
        ))

        # Tool 2: Get threat analysis from Foundation-Sec
        def analyze_threat(args):
            from splunk.hosted_models import get_foundation_sec
            model = get_foundation_sec()
            return model.analyze_threat(args)

        self.register(AgenticTool(
            name="analyze_with_foundation_sec",
            description="Analyze a security event using Splunk Foundation-Sec AI model",
            handler=analyze_threat,
            category="ai"
        ))

        # Tool 3: Get MITRE mapping
        def mitre_map(args):
            from splunk.hosted_models import get_foundation_sec
            model = get_foundation_sec()
            return model.generate_mitre_mapping(args)

        self.register(AgenticTool(
            name="get_mitre_mapping",
            description="Map a security event to MITRE ATT&CK techniques",
            handler=mitre_map,
            category="ai"
        ))

        # Tool 4: Time series prediction
        def predict_ts(args):
            from splunk.hosted_models import get_deep_ts
            model = get_deep_ts()
            return model.predict_metric(
                index=args.get("index", "infrastructure"),
                horizon=args.get("horizon", 5)
            )

        self.register(AgenticTool(
            name="predict_timeseries",
            description="Forecast infrastructure metrics using Cisco Deep Time Series model",
            handler=predict_ts,
            category="ai"
        ))

        # Tool 5: Anomaly detection via AI Toolkit
        def detect_anomalies(args):
            from splunk.ai_toolkit import get_ai_toolkit
            toolkit = get_ai_toolkit()
            return toolkit.apply_anomaly_model(index=args.get("index", "security"))

        self.register(AgenticTool(
            name="detect_anomalies",
            description="Detect anomalies in Splunk data using AI Toolkit",
            handler=detect_anomalies,
            category="ai"
        ))

        # Tool 6: AI-powered threat classification
        def classify_threat(args):
            from splunk.ai_toolkit import get_ai_toolkit
            toolkit = get_ai_toolkit()
            text = args.get("text", args.get("event", ""))
            return toolkit.classify_threat(text)

        self.register(AgenticTool(
            name="classify_threat",
            description="Classify a threat event using AI Toolkit zero-shot classification",
            handler=classify_threat,
            category="ai"
        ))

        # Tool 7: Generate investigation SPL
        def suggest_spl(args):
            from splunk.ai_assistant import get_ai_assistant
            assistant = get_ai_assistant()
            return assistant.suggest_investigation(args)

        self.register(AgenticTool(
            name="suggest_investigation_queries",
            description="Get AI-suggested SPL queries for investigating an incident",
            handler=suggest_spl,
            category="ai_assistant"
        ))

        # Tool 8: NL → SPL
        def nl_to_spl(args):
            from splunk.ai_assistant import get_ai_assistant
            assistant = get_ai_assistant()
            return assistant.generate_spl(
                args.get("question", ""),
                context=args.get("context", {})
            )

        self.register(AgenticTool(
            name="natural_language_search",
            description="Convert a natural language question into an SPL query",
            handler=nl_to_spl,
            category="ai_assistant"
        ))

        # Tool 9: Risk scoring
        def score_risk(args):
            from splunk.ai_toolkit import get_ai_toolkit
            toolkit = get_ai_toolkit()
            return toolkit.score_risk(args)

        self.register(AgenticTool(
            name="score_risk",
            description="Calculate AI-powered risk score for a user context",
            handler=score_risk,
            category="ai"
        ))

        # Tool 10: Capacity forecast
        def forecast_capacity(args):
            from splunk.hosted_models import get_deep_ts
            model = get_deep_ts()
            return model.forecast_capacity(args.get("service", "CustomerDB"))

        self.register(AgenticTool(
            name="forecast_capacity",
            description="Predict capacity requirements for a service using Deep Time Series",
            handler=forecast_capacity,
            category="ai"
        ))

    def register(self, tool):
        """Register an additional tool."""
        self._tools[tool.name] = tool

    def list_tools(self):
        """List all available tools."""
        return [t.to_schema() for t in self._tools.values()]

    def execute(self, tool_name, arguments=None):
        """
        Execute a tool and log the result.

        Returns:
            dict with tool result and metadata
        """
        arguments = arguments or {}
        start = time.time()

        if tool_name not in self._tools:
            result = {"error": f"Unknown tool: {tool_name}"}
            success = False
        else:
            try:
                result = self._tools[tool_name].handler(arguments)
                success = True
            except Exception as e:
                result = {"error": str(e)}
                success = False

        elapsed = round(time.time() - start, 3)

        log_entry = {
            "agent": self.agent_name,
            "tool": tool_name,
            "arguments": arguments,
            "success": success,
            "elapsed_seconds": elapsed,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        self._execution_log.append(log_entry)

        return {
            "tool": tool_name,
            "result": result,
            "success": success,
            "elapsed": elapsed
        }

    def execute_plan(self, plan):
        """
        Execute a sequence of tool calls.

        Args:
            plan: list of dicts with 'tool' and 'args' keys

        Returns:
            list of results from each tool call
        """
        results = []
        for step in plan:
            tool_name = step.get("tool", "")
            args = step.get("args", {})
            result = self.execute(tool_name, args)
            results.append(result)
        return results

    def get_execution_log(self):
        """Return the full execution log."""
        return self._execution_log

    def get_execution_summary(self):
        """Return a summary of all tool executions."""
        if not self._execution_log:
            return {"total_calls": 0, "tools_used": [], "total_time": 0}

        tools_used = list(set(e["tool"] for e in self._execution_log))
        total_time = sum(e.get("elapsed_seconds", 0) for e in self._execution_log)
        successes = sum(1 for e in self._execution_log if e["success"])

        return {
            "agent": self.agent_name,
            "total_calls": len(self._execution_log),
            "successful_calls": successes,
            "failed_calls": len(self._execution_log) - successes,
            "tools_used": tools_used,
            "total_time": round(total_time, 3),
            "ai_tools_used": [t for t in tools_used if self._tools.get(t, AgenticTool("", "", None)).category == "ai"],
            "splunk_tools_used": [t for t in tools_used if self._tools.get(t, AgenticTool("", "", None)).category == "splunk"]
        }


# ── Factory ──────────────────────────────────────────────────────

def create_executor(agent_name):
    """Create a new AgenticToolExecutor for an agent."""
    return AgenticToolExecutor(agent_name)


# ── Test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Agentic Tool Executor Test")
    print("  " + "-" * 50)

    executor = create_executor("Security Agent")
    tools = executor.list_tools()
    print(f"\n  Registered {len(tools)} tools:")
    for t in tools:
        print(f"    [{t['category']}] {t['name']}: {t['description'][:60]}")

    # Execute a plan
    plan = [
        {"tool": "run_spl_search", "args": {"spl": "index=security user=John"}},
        {"tool": "analyze_with_foundation_sec", "args": {"user": "John", "event": "Privilege Escalation", "severity": "Critical"}},
        {"tool": "get_mitre_mapping", "args": {"event": "Privilege Escalation", "severity": "Critical"}},
        {"tool": "classify_threat", "args": {"text": "User John performed Privilege Escalation"}},
        {"tool": "score_risk", "args": {"alerts": ["Priv Esc"], "services": ["CustomerDB"], "blast_radius": 5, "criticality": "High", "touches_sensitive": True}}
    ]

    print(f"\n  Executing {len(plan)}-step plan:")
    results = executor.execute_plan(plan)
    for r in results:
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {r['tool']}: {r['elapsed']}s")

    summary = executor.get_execution_summary()
    print(f"\n  Summary: {summary['total_calls']} calls, {summary['successful_calls']} succeeded, {summary['total_time']}s total")
    print(f"  AI tools: {', '.join(summary['ai_tools_used'])}")
    print("  ✓ Agentic tools operational")

"""
context_provider.py — MCP Context Provider for Agents

Gives agents a single interface to get all the context they need
for reasoning — pulling data through MCP tools from Splunk
and the Digital Twin.

    Agent asks:
        "Give me full context for this incident"
            ↓
    Context Provider
            ↓
    MCP Tools → Splunk
    Graph Queries → Digital Twin
            ↓
    Rich Context Object

This is what makes agents "MCP-powered" — they don't read
CSV files or call Splunk directly. They go through the
Model Context Protocol.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.mcp_tools import MCPToolRegistry
from mcp.splunk_tools import register_splunk_tools
from services.graph_query import (
    get_user_department, get_user_services, get_user_alerts,
    get_criticality, get_affected_systems, get_policies_for_event,
    get_user_devices
)


class MCPContextProvider:
    """
    Provides enriched context to agents by combining:
        1. Live Splunk data via MCP tools
        2. Digital Twin graph relationships

    This is the bridge between agents and data.
    """

    def __init__(self, graph=None):
        self.registry = MCPToolRegistry()
        from mcp.splunk_tools import register_splunk_tools, register_ai_tools
        register_splunk_tools(self.registry)
        register_ai_tools(self.registry)
        self.graph = graph

    def get_incident_context(self, incident):
        """
        Build full context for an incident by querying
        both Splunk (via MCP) and the Digital Twin.

        Returns a rich context dict that agents use for reasoning.
        """
        user = incident.get("user", "Unknown")
        event = incident.get("event", "")
        severity = incident.get("severity", "Medium")

        context = {
            "incident": incident,
            "splunk": {},
            "twin": {},
            "mcp_calls": [],
            "ai_enrichment": {},
            "spl_suggestion": {}
        }

        # ── Splunk Context via MCP ───────────────────────────────

        # 1. Standard: splunk_run_query
        query_res = self.registry.call_tool(
            "splunk_run_query", {"query": f"index=security user={user}", "max_results": 20}
        )
        context["splunk"]["security_events"] = query_res.content
        context["mcp_calls"].append(query_res.to_dict())

        # 2. Standard: splunk_get_user_list
        user_list_res = self.registry.call_tool("splunk_get_user_list", {})
        context["splunk"]["user_list"] = user_list_res.content
        context["mcp_calls"].append(user_list_res.to_dict())

        # 3. Standard: splunk_get_knowledge_objects
        ko_res = self.registry.call_tool("splunk_get_knowledge_objects", {"type": "alert"})
        context["splunk"]["knowledge_objects"] = ko_res.content
        context["mcp_calls"].append(ko_res.to_dict())

        # 4. Standard: saia_generate_spl
        spl_gen_res = self.registry.call_tool(
            "saia_generate_spl", {"question": f"Show all activity for {user} relating to {event}", "context": incident}
        )
        context["splunk"]["generated_spl"] = spl_gen_res.content
        context["mcp_calls"].append(spl_gen_res.to_dict())

        # 5. Standard: splunk_run_saved_search
        saved_search_res = self.registry.call_tool(
            "splunk_run_saved_search", {"name": "critical_privilege_escalation_alert"}
        )
        context["splunk"]["saved_search_results"] = saved_search_res.content
        context["mcp_calls"].append(saved_search_res.to_dict())

        # 6. Standard: splunk_get_info
        info_res = self.registry.call_tool("splunk_get_info", {})
        context["splunk"]["instance_info"] = info_res.content
        context["mcp_calls"].append(info_res.to_dict())

        # ── Legacy Context for backward compatibility ───────────

        # Legacy Business Context
        biz_result = self.registry.call_tool(
            "query_business_context", {"user": user}
        )
        context["splunk"]["business_context"] = biz_result.content
        context["mcp_calls"].append(biz_result.to_dict())

        # Legacy Infrastructure
        infra_result = self.registry.call_tool(
            "query_infrastructure_events", {}
        )
        context["splunk"]["infrastructure"] = infra_result.content
        context["mcp_calls"].append(infra_result.to_dict())

        # Legacy Compliance
        comp_result = self.registry.call_tool(
            "query_compliance_events", {}
        )
        context["splunk"]["compliance"] = comp_result.content
        context["mcp_calls"].append(comp_result.to_dict())

        # Legacy User Activity
        activity_result = self.registry.call_tool(
            "get_user_activity", {"username": user}
        )
        context["splunk"]["user_activity"] = activity_result.content
        context["mcp_calls"].append(activity_result.to_dict())

        # ── Digital Twin Context ─────────────────────────────────

        if self.graph:
            twin = {}
            twin["department"] = get_user_department(self.graph, user)
            twin["services"] = get_user_services(self.graph, user)
            twin["alerts"] = get_user_alerts(self.graph, user)
            twin["criticality"] = get_criticality(self.graph, user)
            twin["devices"] = get_user_devices(self.graph, user)
            twin["affected_systems"] = get_affected_systems(self.graph, user)
            twin["policies"] = get_policies_for_event(self.graph, event)
            context["twin"] = twin

        # ── AI Enhanced Context & Suggestions ────────────────────
        context["ai_enrichment"] = self.get_ai_enhanced_context(incident)
        context["spl_suggestion"] = self.get_spl_suggestion(incident)

        return context

    def get_ai_enhanced_context(self, incident):
        """
        Enriches incident context with Foundation-Sec threat analysis
        and Deep Time Series forecasts.
        """
        user = incident.get("user", "Unknown")
        event = incident.get("event", "")
        severity = incident.get("severity", "Medium")

        # 1. Foundation-Sec threat analysis via MCP tool
        threat_analysis = {}
        try:
            res = self.registry.call_tool("analyze_threat_with_ai", {
                "user": user,
                "event": event,
                "severity": severity,
                "context": f"User is in scope of incident."
            })
            threat_analysis = res.content
        except Exception as e:
            print(f"  [ContextProvider] analyze_threat_with_ai failed: {e}")

        # 2. Deep Time Series metric predictions via MCP tool
        forecast = {}
        try:
            res = self.registry.call_tool("predict_timeseries", {
                "index": "infrastructure",
                "horizon": 5
            })
            forecast = res.content
        except Exception as e:
            print(f"  [ContextProvider] predict_timeseries failed: {e}")

        return {
            "threat_analysis": threat_analysis,
            "forecast": forecast
        }

    def get_spl_suggestion(self, incident):
        """
        Use AI Assistant via MCP tool to suggest SPL queries for investigation.
        """
        try:
            res = self.registry.call_tool("generate_spl_query", {
                "question": f"Show all logs for user {incident.get('user')} related to {incident.get('event')}",
                "context": incident
            })
            return res.content
        except Exception as e:
            print(f"  [ContextProvider] generate_spl_query failed: {e}")
            return {
                "spl": "index=security | head 10",
                "explanation": "Default fallback query"
            }

    def get_security_context(self, user, severity=None):
        """Quick security-focused context pull."""
        args = {"user": user}
        if severity:
            args["severity"] = severity
        result = self.registry.call_tool("query_security_events", args)
        return result.content

    def get_infrastructure_context(self, service=None):
        """Quick infrastructure-focused context pull."""
        args = {}
        if service:
            args["service"] = service
        result = self.registry.call_tool("query_infrastructure_events", args)
        return result.content

    def get_compliance_context(self, risk_level=None):
        """Quick compliance-focused context pull."""
        args = {}
        if risk_level:
            args["risk_level"] = risk_level
        result = self.registry.call_tool("query_compliance_events", args)
        return result.content

    def get_mcp_tool_list(self):
        """Return all available MCP tools."""
        return self.registry.list_tools()

    def get_mcp_call_log(self):
        """Return the log of all MCP calls made during this session."""
        return self.registry.get_call_log()


# ── Test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    from splunk.twin_sync import sync_twin

    print("\n  MCP Context Provider Test")
    print("  " + "-" * 50)

    # Build Digital Twin
    twin = sync_twin()

    # Create context provider
    provider = MCPContextProvider(graph=twin)

    # List tools
    tools = provider.get_mcp_tool_list()
    print(f"\n  MCP Tools available: {len(tools['tools'])}")

    # Get full incident context
    incident = {
        "user": "John",
        "event": "Privilege Escalation",
        "severity": "Critical"
    }

    print(f"\n  Building context for: {incident['event']}")
    ctx = provider.get_incident_context(incident)

    print(f"\n  Splunk Context:")
    print(f"    Security events:  {ctx['splunk']['security_events']['result_count']}")
    print(f"    Business records: {ctx['splunk']['business_context']['result_count']}")
    print(f"    Infra events:     {ctx['splunk']['infrastructure']['result_count']}")
    print(f"    Compliance:       {ctx['splunk']['compliance']['result_count']}")
    print(f"    User activity:    {ctx['splunk']['user_activity']['total_events']}")

    print(f"\n  Digital Twin Context:")
    print(f"    Department:       {ctx['twin']['department']}")
    print(f"    Services:         {', '.join(ctx['twin']['services'][:4])}")
    print(f"    Criticality:      {ctx['twin']['criticality']}")
    print(f"    Blast radius:     {ctx['twin']['affected_systems']['total_impact']}")
    print(f"    Alerts:           {', '.join(ctx['twin']['alerts'][:3])}")

    print(f"\n  MCP calls made: {len(ctx['mcp_calls'])}")
    print("  ✓ Context Provider operational")

"""
Infrastructure Agent — Keeps systems running.

    Digital Twin
        ↓
    Blast Radius Analysis
        ↓
    LLM Reasoning
        ↓
    Infrastructure Assessment

Analyzes the dependency graph to predict service disruption.
"""

from agents.base import AgentOpinion
from services.graph_query import get_user_services, get_affected_systems
from services.llm_client import reason_timeseries
from splunk.agentic_tools import create_executor, AgenticTool


class InfrastructureAgent:

    def analyze(self, incident, graph):
        user = incident["user"]
        event = incident["event"]
        severity = incident["severity"]

        # Initialize the Agentic Tool Executor
        executor = create_executor("Infrastructure Agent")

        # Query the Digital Twin for initial context
        impact = get_affected_systems(graph, user)
        direct = impact["direct"]
        downstream = impact["downstream"]
        total = impact["total_impact"]

        # Check production-critical services dynamically from the graph
        affected_critical = [
            s for s in direct
            if graph.G.nodes.get(s, {}).get("criticality") == "High"
        ]

        # Register custom infrastructure telemetry tool
        def get_service_metrics(args):
            service = args.get("service", "CustomerDB")
            
            # Query Splunk for live metrics if connected
            from splunk.splunk_client import get_client
            client = get_client()
            is_live = type(client).__name__ in ["SplunkClient", "SplunkSDKClient"]
            
            if is_live:
                try:
                    query = f"index=infrastructure service=\"{service}\" | head 1"
                    res = client.search(query, max_results=1)
                    if res and len(res) > 0:
                        row = res[0]
                        return {
                            "service": service,
                            "cpu_utilization": float(row.get("cpu_utilization", 82.5)),
                            "memory_utilization": float(row.get("memory_utilization", 67.1)),
                            "disk_utilization": float(row.get("disk_utilization", 45.9)),
                            "active_connections": int(row.get("active_connections", 1420)),
                            "live_telemetry": True
                        }
                except Exception as e:
                    print(f"  [Infrastructure Agent] Failed to query live service metrics: {e}")
            
            # Fallback mock metrics when offline
            return {
                "service": service,
                "cpu_utilization": 82.5,
                "memory_utilization": 67.1,
                "disk_utilization": 45.9,
                "active_connections": 1420,
                "live_telemetry": False
            }

        executor.register(AgenticTool(
            name="get_service_metrics",
            description="Retrieve real-time resource utilization metrics for a service",
            handler=get_service_metrics,
            category="infrastructure"
        ))

        # Build initial observation
        observation = (
            f"Initial context gathered from Digital Twin:\n"
            f"- Direct services: {', '.join(direct) if direct else 'None'}\n"
            f"- Downstream dependencies: {', '.join(downstream) if downstream else 'None'}\n"
            f"- Total blast radius: {total} systems\n"
            f"- Critical services affected: {', '.join(affected_critical) if affected_critical else 'None'}\n"
        )

        system = (
            "You are the Infrastructure Agent in an Enterprise AI Council. "
            "Your mission is to maintain service reliability and uptime. "
            "You run an agentic loop to forecast resource usage and assess service reliability "
            "using Splunk Deep Time Series tools before arriving at a final assessment."
        )

        # Agentic Loop (Plan-Execute-Observe)
        for iteration in range(2):
            prompt = (
                f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
                f"CURRENT OBSERVATION:\n{observation}\n\n"
                f"As the Infrastructure Agent, do you need to execute a tool to forecast metrics? "
                f"Available tools:\n"
                f"1. 'run_spl_search': Search Splunk metric logs\n"
                f"2. 'get_service_metrics': Get resource utilization metrics for a service\n"
                f"3. 'predict_timeseries': Forecast infrastructure metrics using Deep Time Series\n"
                f"4. 'forecast_capacity': Predict capacity limits for a service using Deep Time Series\n\n"
                f"If you need to call a tool, respond with a JSON object:\n"
                f'{{"call_tool": "tool_name", "args": {{...}}}}\n'
                f"If you have enough information and want to make your final recommendation, respond with:\n"
                f'{{"final_recommendation": True}}\n'
            )

            choice = reason_timeseries(prompt, system, structured=True)

            # Check if choice is already a final recommendation dictionary (due to fallback or early exit)
            if "recommendation" in choice and "risk_level" in choice and "reasoning" in choice:
                reasoning = choice["reasoning"]
                summary = executor.get_execution_summary()
                if summary["total_calls"] > 0:
                    reasoning += f"\n\nAgentic Investigation Summary:\n- Tools used: {', '.join(summary['tools_used'])}\n- Total tools executed: {summary['total_calls']}"
                return AgentOpinion(
                    agent_name="Infrastructure Agent",
                    risk_level=choice["risk_level"],
                    recommendation=choice["recommendation"],
                    confidence=choice["confidence"],
                    reasoning=reasoning
                )

            if choice.get("call_tool"):
                tool_name = choice["call_tool"]
                args = choice.get("args", {})
                print(f"  [Infrastructure Agentic Loop] Calling tool {tool_name} with args {args}")
                tool_res = executor.execute(tool_name, args)
                observation += f"\n[Tool Execution: {tool_name}]\nArgs: {args}\nResult: {tool_res['result']}\n"
            else:
                break

        # Final evaluation
        final_prompt = (
            f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
            f"FORECASTS AND DATA GATHERED:\n{observation}\n\n"
            f"Provide your final infrastructure impact assessment."
        )
        result = reason_timeseries(final_prompt, system, structured=True)

        reasoning = result["reasoning"]
        summary = executor.get_execution_summary()
        if summary["total_calls"] > 0:
            reasoning += f"\n\nAgentic Investigation Summary:\n- Tools used: {', '.join(summary['tools_used'])}\n- Total tools executed: {summary['total_calls']}"

        return AgentOpinion(
            agent_name="Infrastructure Agent",
            risk_level=result["risk_level"],
            recommendation=result["recommendation"],
            confidence=result["confidence"],
            reasoning=reasoning
        )

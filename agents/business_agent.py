"""
Business Agent — Protects business operations.

    Digital Twin
        ↓
    Organizational Context
        ↓
    LLM Reasoning
        ↓
    Business Impact Assessment

Evaluates the business impact of security actions.
"""

from agents.base import AgentOpinion
from services.graph_query import get_user_department, get_user_services, get_criticality
from services.llm_client import reason_security
from splunk.agentic_tools import create_executor, AgenticTool


class BusinessAgent:

    def analyze(self, incident, graph):
        user = incident["user"]
        event = incident["event"]
        severity = incident.get("severity", "Medium")

        # Initialize the Agentic Tool Executor
        executor = create_executor("Business Agent")

        # Query the Digital Twin
        department = get_user_department(graph, user)
        services = get_user_services(graph, user)
        criticality = get_criticality(graph, user)

        # Register custom business tools
        def get_user_criticality(args):
            return {
                "user": user,
                "criticality_level": criticality,
                "access_tier": "Tier-1 Administrator" if criticality == "Critical" else "Tier-2 Operator"
            }

        def assess_revenue_impact(args):
            return {
                "direct_revenue_at_risk": 50000 if criticality == "Critical" else 5000,
                "operational_delay_cost": 25000 if criticality == "Critical" else 2000,
                "sla_violation_risk": "High" if criticality == "Critical" else "Low"
            }

        executor.register(AgenticTool(
            name="get_user_criticality",
            description="Retrieve user business importance and access tier detail",
            handler=get_user_criticality,
            category="business"
        ))

        executor.register(AgenticTool(
            name="assess_revenue_impact",
            description="Calculate predicted revenue and cost risk associated with restricting user access",
            handler=assess_revenue_impact,
            category="business"
        ))

        # Build initial observation
        observation = (
            f"Initial context gathered from Digital Twin:\n"
            f"- Department: {department or 'Unknown'}\n"
            f"- Business criticality: {criticality}\n"
            f"- Connected systems: {', '.join(services[:6]) if services else 'None'}\n"
            f"- Number of system connections: {len(services)}\n"
        )

        system = (
            "You are the Business Agent in an Enterprise AI Council. "
            "Your mission is to minimize business disruption and protect revenue. "
            "You run an agentic loop checking business criticality and revenue impact "
            "using Splunk tools before arriving at a final assessment."
        )

        # Agentic Loop (Plan-Execute-Observe)
        for iteration in range(2):
            prompt = (
                f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
                f"CURRENT OBSERVATION:\n{observation}\n\n"
                f"As the Business Agent, do you need to execute a tool to evaluate business impact? "
                f"Available tools:\n"
                f"1. 'run_spl_search': Search Splunk business activity logs\n"
                f"2. 'get_user_criticality': Look up user department role and tier metadata\n"
                f"3. 'assess_revenue_impact': Estimate revenue risk and cost impacts of blocking\n"
                f"4. 'business_criticality': Check user business significance\n\n"
                f"If you need to call a tool, respond with a JSON object:\n"
                f'{{"call_tool": "tool_name", "args": {{...}}}}\n'
                f"If you have enough information and want to make your final recommendation, respond with:\n"
                f'{{"final_recommendation": True}}\n'
            )

            choice = reason_security(prompt, system, structured=True)

            # Check if choice is already a final recommendation dictionary (due to fallback or early exit)
            if "recommendation" in choice and "risk_level" in choice and "reasoning" in choice:
                reasoning = choice["reasoning"]
                summary = executor.get_execution_summary()
                if summary["total_calls"] > 0:
                    reasoning += f"\n\nAgentic Investigation Summary:\n- Tools used: {', '.join(summary['tools_used'])}\n- Total tools executed: {summary['total_calls']}"
                return AgentOpinion(
                    agent_name="Business Agent",
                    risk_level=choice["risk_level"],
                    recommendation=choice["recommendation"],
                    confidence=choice["confidence"],
                    reasoning=reasoning
                )

            if choice.get("call_tool"):
                tool_name = choice["call_tool"]
                args = choice.get("args", {})
                print(f"  [Business Agentic Loop] Calling tool {tool_name} with args {args}")
                tool_res = executor.execute(tool_name, args)
                observation += f"\n[Tool Execution: {tool_name}]\nArgs: {args}\nResult: {tool_res['result']}\n"
            else:
                break

        # Final evaluation
        final_prompt = (
            f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
            f"BUSINESS CONTEXT GATHERED:\n{observation}\n\n"
            f"Provide your final business impact assessment."
        )
        result = reason_security(final_prompt, system, structured=True)

        reasoning = result["reasoning"]
        summary = executor.get_execution_summary()
        if summary["total_calls"] > 0:
            reasoning += f"\n\nAgentic Investigation Summary:\n- Tools used: {', '.join(summary['tools_used'])}\n- Total tools executed: {summary['total_calls']}"

        return AgentOpinion(
            agent_name="Business Agent",
            risk_level=result["risk_level"],
            recommendation=result["recommendation"],
            confidence=result["confidence"],
            reasoning=reasoning
        )

"""
Security Agent — Protects the organization.

    Digital Twin
        ↓
    LLM Reasoning
        ↓
    Security Assessment

Now powered by LLM reasoning over Digital Twin relationships.
"""

from agents.base import AgentOpinion
from services.graph_query import get_user_alerts, get_user_services, get_criticality
from services.llm_client import reason_security
from splunk.agentic_tools import create_executor, AgenticTool

MITRE_ATTACK_MAPPING = {
    "Privilege Escalation": "T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control) / T1078 (Valid Accounts)",
    "Large Data Download": "T1114.002 (Email Collection: Remote Email Collection) / T1020 (Automated Exfiltration)",
    "Sensitive File Copy": "T1048.002 (Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Channel)",
    "CPU Spike": "T1496 (Resource Hijacking)",
    "Outage Alert": "T1489 (Service Stop)",
    "VPN Anomaly": "T1133 (External Remote Services)"
}


class SecurityAgent:

    def analyze(self, incident, graph):
        user = incident["user"]
        event = incident["event"]
        severity = incident["severity"]

        # Initialize the Agentic Tool Executor for first-class Splunk App agent behavior
        executor = create_executor("Security Agent")

        # Query the Digital Twin for initial context
        alerts = get_user_alerts(graph, user)
        services = get_user_services(graph, user)
        criticality = get_criticality(graph, user)

        # Check for sensitive system access dynamically from the graph
        touches_sensitive = [
            s for s in services
            if graph.G.nodes.get(s, {}).get("criticality") == "High"
        ]

        # Register custom threat intelligence tool
        def get_threat_intel(args):
            return {
                "reputation": "malicious" if severity == "Critical" else "suspicious",
                "known_ips": ["192.168.1.50", "10.0.4.12"],
                "threat_feeds_matched": ["ThreatStream", "AlienVault"]
            }

        executor.register(AgenticTool(
            name="get_threat_intel",
            description="Look up external threat intelligence feed details for the event",
            handler=get_threat_intel,
            category="ai"
        ))

        # Build execution log / observation context
        observation = (
            f"Initial context gathered from Digital Twin:\n"
            f"- Alerts targeting this user: {', '.join(alerts) if alerts else 'None'}\n"
            f"- Systems accessed: {', '.join(services) if services else 'None'}\n"
            f"- User criticality: {criticality}\n"
            f"- Sensitive systems accessed: {', '.join(touches_sensitive) if touches_sensitive else 'None'}\n"
            f"- Total alert count: {len(alerts)}\n"
        )

        system = (
            "You are the Security Agent in an Enterprise AI Council. "
            "Your mission is to protect the company from threats. "
            "You run an agentic loop investigating security events using Splunk tools "
            "before arriving at a final assessment."
        )

        # Agentic Loop (Plan-Execute-Observe)
        for iteration in range(2):
            prompt = (
                f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
                f"CURRENT OBSERVATION:\n{observation}\n\n"
                f"As the Security Agent, do you need to execute a tool to investigate further? "
                f"Available tools:\n"
                f"1. 'run_spl_search': Search Splunk log history (e.g. check login history or recent file activity)\n"
                f"2. 'get_threat_intel': Look up external threat intelligence feed details\n"
                f"3. 'analyze_with_foundation_sec': Analyze threat using Foundation-Sec AI model\n"
                f"4. 'get_mitre_mapping': Get MITRE ATT&CK techniques mapping\n"
                f"5. 'classify_threat': Classify threat event using AI Toolkit\n"
                f"6. 'score_risk': Calculate risk score using AI Toolkit\n\n"
                f"If you need to call a tool, respond with a JSON object:\n"
                f'{{"call_tool": "tool_name", "args": {{...}}}}\n'
                f"If you have enough information and want to make your final recommendation, respond with:\n"
                f'{{"final_recommendation": True}}\n'
            )

            choice = reason_security(prompt, system, structured=True)

            # Check if choice is already a final recommendation dictionary (due to fallback or early exit)
            if "recommendation" in choice and "risk_level" in choice and "reasoning" in choice:
                # Add investigation summary to the reasoning
                reasoning = choice["reasoning"]
                summary = executor.get_execution_summary()
                if summary["total_calls"] > 0:
                    reasoning += f"\n\nAgentic Investigation Summary:\n- Tools used: {', '.join(summary['tools_used'])}\n- Total tools executed: {summary['total_calls']}"
                
                # Append MITRE ATT&CK Mapping
                mitre_mapping = MITRE_ATTACK_MAPPING.get(event, "T1078 (Valid Accounts)")
                reasoning += f"\n\nMITRE ATT&CK Mapping:\n- Techniques: {mitre_mapping}"

                return AgentOpinion(
                    agent_name="Security Agent",
                    risk_level=choice["risk_level"],
                    recommendation=choice["recommendation"],
                    confidence=choice["confidence"],
                    reasoning=reasoning
                )

            if choice.get("call_tool"):
                tool_name = choice["call_tool"]
                args = choice.get("args", {})
                print(f"  [Security Agentic Loop] Calling tool {tool_name} with args {args}")
                tool_res = executor.execute(tool_name, args)
                observation += f"\n[Tool Execution: {tool_name}]\nArgs: {args}\nResult: {tool_res['result']}\n"
            else:
                break

        # Final evaluation
        final_prompt = (
            f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
            f"INVESTIGATION DATA GATHERED:\n{observation}\n\n"
            f"Provide your final security assessment."
        )
        result = reason_security(final_prompt, system, structured=True)

        reasoning = result["reasoning"]
        summary = executor.get_execution_summary()
        if summary["total_calls"] > 0:
            reasoning += f"\n\nAgentic Investigation Summary:\n- Tools used: {', '.join(summary['tools_used'])}\n- Total tools executed: {summary['total_calls']}"

        # Append MITRE ATT&CK Mapping
        mitre_mapping = MITRE_ATTACK_MAPPING.get(event, "T1078 (Valid Accounts)")
        reasoning += f"\n\nMITRE ATT&CK Mapping:\n- Techniques: {mitre_mapping}"

        return AgentOpinion(
            agent_name="Security Agent",
            risk_level=result["risk_level"],
            recommendation=result["recommendation"],
            confidence=result["confidence"],
            reasoning=reasoning
        )

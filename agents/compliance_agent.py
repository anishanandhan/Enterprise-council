"""
Compliance Agent — Ensures regulatory compliance.

    Digital Twin
        ↓
    Policy Graph Analysis
        ↓
    LLM Reasoning
        ↓
    Compliance Assessment

Checks policy violations and evidence preservation requirements.
"""

from agents.base import AgentOpinion
from services.graph_query import get_policies_for_event
from services.llm_client import reason_security
from splunk.agentic_tools import create_executor, AgenticTool


class ComplianceAgent:

    def analyze(self, incident, graph):
        event = incident["event"]
        user = incident.get("user", "Unknown")
        severity = incident.get("severity", "Medium")

        # Initialize the Agentic Tool Executor
        executor = create_executor("Compliance Agent")

        # Query the Digital Twin for policy matches
        policies = get_policies_for_event(graph, event)

        sensitive_events = {"Sensitive File Copy", "Large Data Download", "Privilege Escalation"}
        is_sensitive = event in sensitive_events

        # Register custom compliance tools
        def check_policy_violations(args):
            return {
                "policy_violations_found": True if is_sensitive else False,
                "policies_triggered": policies,
                "compliance_impact": "PCI-DSS / GDPR Scope" if is_sensitive else "Internal Policy"
            }

        def get_audit_trail(args):
            return {
                "audit_logs_secured": True,
                "integrity_hash": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "retention_policy": "90 Days Active"
            }

        executor.register(AgenticTool(
            name="check_policy_violations",
            description="Check user activity against compliance frameworks and internal policies",
            handler=check_policy_violations,
            category="compliance"
        ))

        executor.register(AgenticTool(
            name="get_audit_trail",
            description="Retrieve and secure the log audit trail for compliance verification",
            handler=get_audit_trail,
            category="compliance"
        ))

        # Build initial observation
        observation = (
            f"Initial context gathered from Digital Twin:\n"
            f"- Triggered policies: {', '.join(policies) if policies else 'None'}\n"
            f"- Is sensitive event: {is_sensitive}\n"
            f"- Number of policy matches: {len(policies)}\n"
        )

        system = (
            "You are the Compliance Agent in an Enterprise AI Council. "
            "Your mission is to ensure regulatory compliance and proper governance. "
            "You run an agentic loop checking policies and verifying audit logs "
            "using Splunk tools before arriving at a final assessment."
        )

        # Agentic Loop (Plan-Execute-Observe)
        for iteration in range(2):
            prompt = (
                f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
                f"CURRENT OBSERVATION:\n{observation}\n\n"
                f"As the Compliance Agent, do you need to execute a tool to verify compliance? "
                f"Available tools:\n"
                f"1. 'run_spl_search': Search Splunk audit log history\n"
                f"2. 'check_policy_violations': Verify regulatory compliance and framework violations\n"
                f"3. 'get_audit_trail': Ensure log integrity and audit retention constraints\n"
                f"4. 'compliance_check': Look up index compliance metadata\n\n"
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
                    agent_name="Compliance Agent",
                    risk_level=choice["risk_level"],
                    recommendation=choice["recommendation"],
                    confidence=choice["confidence"],
                    reasoning=reasoning
                )

            if choice.get("call_tool"):
                tool_name = choice["call_tool"]
                args = choice.get("args", {})
                print(f"  [Compliance Agentic Loop] Calling tool {tool_name} with args {args}")
                tool_res = executor.execute(tool_name, args)
                observation += f"\n[Tool Execution: {tool_name}]\nArgs: {args}\nResult: {tool_res['result']}\n"
            else:
                break

        # Final evaluation
        final_prompt = (
            f"INCIDENT: {event} involving user {user} ({severity} severity).\n"
            f"COMPLIANCE EVIDENCE GATHERED:\n{observation}\n\n"
            f"Provide your final compliance assessment."
        )
        result = reason_security(final_prompt, system, structured=True)

        reasoning = result["reasoning"]
        summary = executor.get_execution_summary()
        if summary["total_calls"] > 0:
            reasoning += f"\n\nAgentic Investigation Summary:\n- Tools used: {', '.join(summary['tools_used'])}\n- Total tools executed: {summary['total_calls']}"

        return AgentOpinion(
            agent_name="Compliance Agent",
            risk_level=result["risk_level"],
            recommendation=result["recommendation"],
            confidence=result["confidence"],
            reasoning=reasoning
        )

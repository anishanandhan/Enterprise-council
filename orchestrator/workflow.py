"""
workflow.py — Enterprise Council Orchestrator (Full Pipeline)

    Splunk
        ↓
    MCP Server
        ↓
    Digital Twin
        ↓
    Agent Planner
        ↓
    Dynamic Council
        ↓
    Agent Debate
        ↓
    Impact Simulation
        ↓
    Council Consensus
        ↓
    Recommended Action
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from splunk.twin_sync import sync_twin
from orchestrator.agent_planner import plan_council
from agents.council_agent import CouncilAgent
from simulation.impact_engine import simulate
from mcp.context_provider import MCPContextProvider
from debate.debate_engine import DebateEngine
from debate.transcript_generator import TranscriptGenerator


def run_council(incident, verbose=True):
    """
    Run the full Enterprise Council pipeline.

    Returns a comprehensive result dict with all stages.
    """
    result = {
        "incident": incident,
        "stages": {}
    }

    # ── Stage 1: Sync Digital Twin ───────────────────────────────

    if verbose:
        print("\n" + "=" * 60)
        print("  ENTERPRISE COUNCIL AI")
        print("=" * 60)
        print("\n  Stage 1: Syncing Digital Twin from Splunk...")

    twin = sync_twin()
    summary = twin.summary()
    result["stages"]["twin"] = summary

    if verbose:
        print(f"    Graph: {summary['nodes']} nodes, {summary['edges']} edges")

    # ── Stage 2: MCP Context Enrichment ──────────────────────────

    if verbose:
        print("\n  Stage 2: Enriching context via MCP tools...")

    mcp_provider = MCPContextProvider(graph=twin)
    mcp_context = mcp_provider.get_incident_context(incident)
    result["stages"]["mcp"] = {
        "tools_available": len(mcp_provider.get_mcp_tool_list()["tools"]),
        "calls_made": len(mcp_context["mcp_calls"]),
        "splunk_events": {
            "security": mcp_context["splunk"]["security_events"]["result_count"],
            "business": mcp_context["splunk"]["business_context"]["result_count"],
            "infrastructure": mcp_context["splunk"]["infrastructure"]["result_count"],
            "compliance": mcp_context["splunk"]["compliance"]["result_count"],
        }
    }

    if verbose:
        print(f"    MCP Tools: {result['stages']['mcp']['tools_available']}")
        print(f"    MCP Calls: {result['stages']['mcp']['calls_made']}")
        for idx, ev in result["stages"]["mcp"]["splunk_events"].items():
            print(f"      {idx}: {ev} events")

    # ── Stage 2.5: AI Assistant Investigation ────────────────────

    if verbose:
        print("\n  Stage 2.5: Running AI Assistant investigation queries...")

    from splunk.ai_assistant import get_ai_assistant
    from splunk.splunk_client import get_client
    assistant = get_ai_assistant()
    client = get_client()

    suggested_queries = assistant.suggest_investigation(incident)
    investigation_results = []

    for sug in suggested_queries[:3]:  # Run top 3 queries to keep it concise
        spl = sug["spl"]
        desc = sug["description"]
        priority = sug["priority"]

        try:
            search_results = client.search(spl, max_results=5)
            investigation_results.append({
                "description": desc,
                "spl": spl,
                "priority": priority,
                "result_count": len(search_results),
                "results": search_results
            })
            if verbose:
                print(f"    Suggest [{priority}]: {desc}")
                print(f"      SPL: {spl}")
                print(f"      Found {len(search_results)} matching events")
        except Exception as e:
            if verbose:
                print(f"      Failed running search: {e}")

    result["stages"]["ai_assistant_investigation"] = {
        "queries_run": len(investigation_results),
        "details": investigation_results
    }

    # ── Stage 3: Incident Classification ─────────────────────────

    if verbose:
        print("\n" + "-" * 60)
        print("  Stage 3: INCIDENT CLASSIFICATION")
        print("-" * 60)

    plan = plan_council(incident)
    classification = plan["classification"]
    result["stages"]["classification"] = classification

    if verbose:
        print(f"    Event:    {classification['event']}")
        print(f"    Category: {classification['category']}")
        print(f"    Priority: {classification['priority']}")
        print(f"    Domains:  {', '.join(classification['domains'])}")
        print(f"    Council:  {plan['council_size']} agents assembled")

    # ── Stage 4: Agent Analysis ──────────────────────────────────

    if verbose:
        print("\n" + "-" * 60)
        print("  Stage 4: AGENT ANALYSIS")
        print("-" * 60)

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(plan["agents"])) as executor:
        futures = [executor.submit(agent.analyze, incident, twin) for agent in plan["agents"]]
        opinions = [f.result() for f in futures]

    result["stages"]["opinions"] = [
        {
            "agent": o.agent_name,
            "risk_level": o.risk_level,
            "recommendation": o.recommendation,
            "confidence": o.confidence,
            "reasoning": o.reasoning
        }
        for o in opinions
    ]

    if verbose:
        print()
        for opinion in opinions:
            print(f"  {opinion.agent_name}:")
            print(f"    Risk:           {opinion.risk_level}")
            print(f"    Recommendation: {opinion.recommendation}")
            print(f"    Confidence:     {opinion.confidence}")
            print(f"    Reasoning:      {opinion.reasoning[:120]}...")
            print()

    # ── Stage 5: Impact Simulation ───────────────────────────────

    if verbose:
        print("=" * 60)
        print("  Stage 5: IMPACT SIMULATION")
        print("=" * 60)

    sim_result = simulate(incident, twin)
    result["stages"]["simulation"] = sim_result

    if verbose:
        print(f"\n    Target: {sim_result['user_context']['user']}")
        print(f"    Criticality: {sim_result['user_context']['criticality']}")
        print(f"    Blast Radius: {sim_result['user_context']['blast_radius']} systems")
        print()

        for sim in sim_result["simulations"]:
            marker = " ◀ RECOMMENDED" if sim["action"] == sim_result["recommended_action"] else ""
            print(f"    ┌─ {sim['description'].upper()}{marker}")
            print(f"    │  Security Risk:   {sim['security_risk']}%")
            print(f"    │  Business Risk:   {sim['business_risk']}%")
            print(f"    │  Compliance Risk: {sim['compliance_risk']}%")
            print(f"    └─ Total Risk:      {sim['total_risk']}%")
            print()

    # ── Stage 6: Agent Debate ────────────────────────────────────

    if verbose:
        print("=" * 60)
        print("  Stage 6: AGENT DEBATE")
        print("=" * 60)

    debate_engine = DebateEngine()
    debate_result = debate_engine.run_debate(opinions, simulation=sim_result)
    result["stages"]["debate"] = debate_result

    if verbose:
        transcript_text = TranscriptGenerator.format_console(debate_result)
        print(transcript_text)

    # ── Stage 7: Council Consensus ───────────────────────────────

    council = CouncilAgent()
    decision = council.decide(opinions, simulation=sim_result)
    result["stages"]["decision"] = decision

    if verbose:
        print("\n" + "=" * 60)
        print("  Stage 7: COUNCIL CONSENSUS")
        print("=" * 60)

        print("\n  Votes:")
        for vote in decision["votes"]:
            print(f"    {vote['agent']}: "
                  f"Risk={vote['risk']}  "
                  f"Weight={vote['weight']}  "
                  f"Score={vote['score']}")

        print(f"\n  ┌─────────────────────────────────────────┐")
        print(f"  │  FINAL DECISION                         │")
        print(f"  ├─────────────────────────────────────────┤")
        print(f"  │  Decision:   {decision['decision']:<27}│")
        print(f"  │  Confidence: {int(decision['confidence'] * 100)}%{' ' * 24}│")
        print(f"  │  Risk Level: {decision['overall_risk']:<27}│")
        if "simulation_recommended" in decision:
            print(f"  │  Backed by:  Impact Simulation{' ' * 9}│")
        print(f"  └─────────────────────────────────────────┘")

        print("\n" + "=" * 60)
        print("  COUNCIL SESSION COMPLETE")
        print("=" * 60 + "\n")

    return result


if __name__ == "__main__":

    print("\n" + "#" * 60)
    print("  SCENARIO 1: Privilege Escalation (Insider Threat)")
    print("#" * 60)

    result1 = run_council({
        "user": "John",
        "event": "Privilege Escalation",
        "severity": "Critical"
    })

    print("\n" + "#" * 60)
    print("  SCENARIO 2: CPU Spike (Infrastructure Failure)")
    print("#" * 60)

    result2 = run_council({
        "user": "System",
        "event": "CPU Spike",
        "severity": "Medium"
    })

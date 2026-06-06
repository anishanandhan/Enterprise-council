"""
debate_engine.py — Multi-Agent Debate System

Instead of agents just voting, they argue.

    Round 1: Initial Opinions
        ↓
    Round 2: Agents respond to each other
        ↓
    Round 3: Final positions
        ↓
    Council synthesizes consensus

This produces the debate transcript that becomes
one of the most impressive parts of the demo.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.llm_client import reason


class DebateEngine:
    """
    Orchestrates a multi-round debate between agents.

    Each agent sees what other agents said and can respond,
    creating genuine disagreement and compromise.
    """

    def __init__(self, max_rounds=3):
        self.max_rounds = max_rounds
        self.transcript = []

    def run_debate(self, opinions, simulation=None):
        """
        Run a structured debate between agents.

        Args:
            opinions: list of AgentOpinion from the initial analysis
            simulation: optional impact simulation results

        Returns:
            dict with debate_rounds, final_positions, and transcript
        """
        rounds = []

        # ── Round 1: Opening Statements ──────────────────────────

        round1 = {
            "round": 1,
            "title": "Opening Statements",
            "statements": []
        }

        for opinion in opinions:
            statement = {
                "agent": opinion.agent_name,
                "position": opinion.recommendation,
                "risk_level": opinion.risk_level,
                "argument": opinion.reasoning,
                "confidence": opinion.confidence
            }
            round1["statements"].append(statement)
            self.transcript.append(
                f"[Round 1] {opinion.agent_name}: {opinion.reasoning}"
            )

        rounds.append(round1)

        # ── Round 2: Cross-Examination ───────────────────────────
        #    Each agent responds to the highest-risk opposing view

        round2 = {
            "round": 2,
            "title": "Cross-Examination",
            "statements": []
        }

        for i, opinion in enumerate(opinions):
            # Find the agent with the most different position
            others = [o for j, o in enumerate(opinions) if j != i]
            if not others:
                continue

            # Pick the agent with the biggest risk disagreement
            opponent = max(others, key=lambda o: abs(
                self._risk_score(o.risk_level) -
                self._risk_score(opinion.risk_level)
            ))

            # Dynamically formulate investigation queries via saia_generate_spl
            evidence = ""
            spl_query = ""
            try:
                from splunk.mcp_client import get_mcp_server
                mcp_server = get_mcp_server()
                
                # Get the domain index mapping for the querying agent
                agent_index_map = {
                    "Security Agent": "security",
                    "Compliance Agent": "compliance",
                    "Infrastructure Agent": "infrastructure",
                    "Business Agent": "business"
                }
                agent_domain_index = agent_index_map.get(opinion.agent_name, "security")
                
                # Retrieve user under investigation
                target_user = "John"
                if simulation and "user_context" in simulation:
                    target_user = simulation["user_context"].get("user", "John")
                
                agent_stance = f"{opponent.agent_name}'s stance that we should {opponent.recommendation}"
                
                question = (
                    f"Generate a Splunk SPL query to find evidence in the {agent_domain_index} index "
                    f"that supports or disproves this agent position: {agent_stance}\n"
                    f"The query MUST search index={agent_domain_index} not any other index.\n"
                    f"User under investigation: {target_user}\n"
                    f"Return only the SPL query, nothing else."
                )
                spl_gen = mcp_server.call_tool("saia_generate_spl", {"question": question})
                if not spl_gen.is_error and spl_gen.content and "spl" in spl_gen.content:
                    spl_query = spl_gen.content["spl"]
                    # Execute Splunk query live
                    query_run = mcp_server.call_tool("splunk_run_query", {"query": spl_query, "max_results": 2})
                    if not query_run.is_error and query_run.content:
                        res_count = query_run.content.get("result_count", 0)
                        evidence = f"Ran live query via MCP: `{spl_query}` -> {res_count} events found."
                        if res_count > 0:
                            sample = query_run.content.get("results", [{}])[0]
                            # Clean up sample dictionary to print compactly
                            clean_sample = {k: v for k, v in sample.items() if not k.startswith("_")}
                            evidence += f" Sample event: {clean_sample}"
            except Exception as e:
                evidence = f"Failed to retrieve dynamic evidence via MCP: {str(e)}"

            rebuttal = self._generate_rebuttal(opinion, opponent, simulation, evidence)

            statement = {
                "agent": opinion.agent_name,
                "responding_to": opponent.agent_name,
                "argument": rebuttal,
                "spl_query": spl_query
            }
            round2["statements"].append(statement)
            self.transcript.append(
                f"[Round 2] {opinion.agent_name} → {opponent.agent_name}: {rebuttal}"
            )

        rounds.append(round2)

        # ── Round 3: Final Positions ─────────────────────────────

        round3 = {
            "round": 3,
            "title": "Final Positions",
            "statements": []
        }

        for opinion in opinions:
            final = self._generate_final_position(opinion, opinions, simulation)
            statement = {
                "agent": opinion.agent_name,
                "final_position": final,
                "maintains_original": True
            }
            round3["statements"].append(statement)
            self.transcript.append(
                f"[Round 3] {opinion.agent_name}: {final}"
            )

        rounds.append(round3)

        return {
            "rounds": rounds,
            "total_rounds": len(rounds),
            "transcript": self.transcript,
            "participants": [o.agent_name for o in opinions]
        }

    def _risk_score(self, level):
        """Convert risk level to numeric score for comparison."""
        return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(level, 0)

    def _generate_rebuttal(self, agent, opponent, simulation, evidence=""):
        """Generate agent's response to an opposing view."""
        prompt = (
            f"DEBATE REBUTTAL\n"
            f"===============\n"
            f"You are: {agent.agent_name}\n"
            f"Your position: {agent.recommendation} (Risk: {agent.risk_level})\n"
            f"Your reasoning: {agent.reasoning}\n\n"
            f"Opponent: {opponent.agent_name}\n"
            f"Their position: {opponent.recommendation} (Risk: {opponent.risk_level})\n"
            f"Their reasoning: {opponent.reasoning}\n\n"
        )

        if evidence:
            prompt += f"REAL-TIME SPLUNK EVIDENCE DISCOVERED MID-DEBATE:\n{evidence}\n\n"

        if simulation:
            prompt += (
                f"Impact simulation shows recommended action: "
                f"{simulation.get('recommended_action', 'unknown')}\n\n"
            )

        prompt += (
            f"Respond to {opponent.agent_name}'s position from your perspective. "
            f"Be specific about WHY your concern matters more, referencing the real-time Splunk evidence if relevant. "
            f"Keep it to 2-3 sentences."
        )

        system = (
            f"You are {agent.agent_name} in an enterprise AI debate. "
            f"Defend your position while acknowledging valid points."
        )

        return reason(prompt, system)

    def _generate_final_position(self, agent, all_opinions, simulation):
        """Generate agent's final position after hearing all arguments."""
        other_positions = "\n".join([
            f"  {o.agent_name}: {o.recommendation} ({o.risk_level})"
            for o in all_opinions if o.agent_name != agent.agent_name
        ])

        prompt = (
            f"FINAL POSITION\n"
            f"==============\n"
            f"You are: {agent.agent_name}\n"
            f"Your initial position: {agent.recommendation}\n\n"
            f"Other agents' positions:\n{other_positions}\n\n"
        )

        if simulation:
            prompt += (
                f"Impact simulation recommends: "
                f"{simulation.get('recommended_action', 'unknown')}\n\n"
            )

        prompt += (
            f"State your final position in 1-2 sentences. "
            f"You may adjust your stance based on new evidence."
        )

        system = f"You are {agent.agent_name}. Give your final concise position."

        return reason(prompt, system)

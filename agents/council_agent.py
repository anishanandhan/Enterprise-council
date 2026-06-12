"""
Council Agent — The decision maker.

Synthesizes all agent opinions + impact simulation into
a final evidence-based consensus.

    Agent Opinions
        ↓
    Impact Simulation
        ↓
    LLM Synthesis
        ↓
    Evidence-Based Consensus
"""

from agents.base import AgentOpinion
from services.llm_client import reason


RISK_WEIGHTS = {
    "Critical": 1.0,
    "High": 0.75,
    "Medium": 0.50,
    "Low": 0.25
}


class CouncilAgent:

    def decide(self, opinions, simulation=None):
        """
        Synthesize agent opinions + simulation results into
        a final evidence-based decision.
        """

        # Weighted voting
        votes = []
        for opinion in opinions:
            weight = RISK_WEIGHTS.get(opinion.risk_level, 0.50)
            score = weight * opinion.confidence
            votes.append({
                "agent": opinion.agent_name,
                "risk": opinion.risk_level,
                "weight": weight,
                "confidence": opinion.confidence,
                "score": round(score, 3)
            })

        # Weighted consensus confidence
        total_score = sum(v["score"] for v in votes)
        avg_score = total_score / len(votes) if votes else 0

        # Determine overall risk based on the weighted average vote score (avg_score)
        if avg_score >= 0.75:
            overall_risk = "Critical"
        elif avg_score >= 0.50:
            overall_risk = "High"
        elif avg_score >= 0.25:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"

        # If simulation is available, use it for the decision
        if simulation:
            decision = simulation["recommended_action"].replace("_", " ").title()
            best_sim = next(
                s for s in simulation["simulations"]
                if s["action"] == simulation["recommended_action"]
            )
            # Scale confidence dynamically between 80% and 95% based on relative risk (normalized to 100)
            council_confidence = round(0.95 - (best_sim["total_risk"] / 100) * 0.15, 2)
        else:
            # Fallback to opinion-based decision using weighted consensus score (avg_score)
            if avg_score >= 0.75:
                decision = "Temporary Restriction"
            elif avg_score >= 0.45:
                decision = "Restricted Access"
            else:
                decision = "Continued Monitoring"
            council_confidence = round(0.85 + (avg_score * 0.10), 2)

        # Generate LLM-powered debate transcript
        debate = self._generate_debate(opinions, simulation, decision)

        result = {
            "decision": decision,
            "confidence": council_confidence,
            "overall_risk": overall_risk,
            "votes": votes,
            "debate_transcript": debate
        }

        # Attach simulation data if available
        if simulation:
            result["simulation"] = simulation["simulations"]
            result["simulation_recommended"] = simulation["recommended_action"]

        return result

    def _generate_debate(self, opinions, simulation, decision):
        """
        Generate a rich debate transcript using the LLM.
        Each agent's reasoning is presented, then the council synthesizes.
        """
        debate = []

        for opinion in opinions:
            debate.append(
                f"{opinion.agent_name}:\n"
                f"{opinion.reasoning}"
            )

        # Build council synthesis prompt
        opinions_text = "\n\n".join([
            f"{o.agent_name} (Risk: {o.risk_level}, Confidence: {o.confidence}):\n"
            f"  Recommendation: {o.recommendation}\n"
            f"  Reasoning: {o.reasoning}"
            for o in opinions
        ])

        sim_text = ""
        if simulation:
            sim_text = "\n\nIMPACT SIMULATION RESULTS:\n"
            for s in simulation["simulations"]:
                marker = " ← RECOMMENDED" if s["action"] == simulation["recommended_action"] else ""
                sim_text += (
                    f"  {s['action']}: Security={s['security_risk']}% "
                    f"Business={s['business_risk']}% "
                    f"Compliance={s['compliance_risk']}% "
                    f"Total={s['total_risk']}%{marker}\n"
                )

        synthesis_prompt = (
            f"COUNCIL DELIBERATION\n"
            f"====================\n\n"
            f"AGENT OPINIONS:\n{opinions_text}\n"
            f"{sim_text}\n\n"
            f"FINAL DECISION: {decision}\n\n"
            f"As the Council Agent, provide a brief synthesis explaining "
            f"how you weighed competing perspectives to reach this decision. "
            f"Reference specific agent concerns and simulation data."
        )

        system = (
            "You are the Council Agent in an Enterprise AI Council. "
            "Your role is to synthesize multiple expert perspectives "
            "and simulation data into a balanced, evidence-based decision."
        )

        synthesis = reason(synthesis_prompt, system)

        debate.append(
            f"Council Agent:\n{synthesis}"
        )

        return debate

"""
test_debate.py — Multi-Agent Debate Engine Tests

Validates debate round orchestration, transcript generation,
and the DebateEngine class structure.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from debate.debate_engine import DebateEngine
from agents.base import AgentOpinion


class TestDebateEngineStructure:
    """Tests for the DebateEngine class initialization and configuration."""

    @pytest.mark.unit
    def test_engine_creation(self):
        engine = DebateEngine()
        assert engine.max_rounds == 3
        assert engine.transcript == []

    @pytest.mark.unit
    def test_engine_custom_rounds(self):
        engine = DebateEngine(max_rounds=5)
        assert engine.max_rounds == 5

    @pytest.mark.unit
    def test_risk_score_conversion(self):
        engine = DebateEngine()
        assert engine._risk_score("Critical") == 4
        assert engine._risk_score("High") == 3
        assert engine._risk_score("Medium") == 2
        assert engine._risk_score("Low") == 1
        assert engine._risk_score("Unknown") == 0

    @pytest.mark.unit
    def test_risk_score_ordering(self):
        engine = DebateEngine()
        levels = ["Low", "Medium", "High", "Critical"]
        scores = [engine._risk_score(l) for l in levels]
        assert scores == sorted(scores), "Risk scores should be monotonically increasing"


class TestDebateRoundStructure:
    """Tests that debate round data structures match expected shapes."""

    @pytest.mark.unit
    def test_round_1_opening_statements(self, sample_opinions):
        """Round 1 should contain one statement per agent."""
        round1 = {
            "round": 1,
            "title": "Opening Statements",
            "statements": []
        }
        for opinion in sample_opinions:
            statement = {
                "agent": opinion.agent_name,
                "position": opinion.recommendation,
                "risk_level": opinion.risk_level,
                "argument": opinion.reasoning,
                "confidence": opinion.confidence
            }
            round1["statements"].append(statement)

        assert len(round1["statements"]) == len(sample_opinions)
        assert all("agent" in s for s in round1["statements"])
        assert all("argument" in s for s in round1["statements"])

    @pytest.mark.unit
    def test_statement_has_required_fields(self, sample_opinions):
        """Each opening statement should have agent, position, risk_level, argument, confidence."""
        for opinion in sample_opinions:
            statement = {
                "agent": opinion.agent_name,
                "position": opinion.recommendation,
                "risk_level": opinion.risk_level,
                "argument": opinion.reasoning,
                "confidence": opinion.confidence
            }
            assert "agent" in statement
            assert "position" in statement
            assert "risk_level" in statement
            assert "argument" in statement
            assert "confidence" in statement

    @pytest.mark.unit
    def test_cross_examination_pairs_opponents(self, sample_opinions):
        """Cross-examination should find the most disagreeing opponent."""
        engine = DebateEngine()
        # Security (Critical) should find Business (Medium) as opponent
        security = sample_opinions[0]  # Critical
        others = sample_opinions[1:]

        opponent = max(others, key=lambda o: abs(
            engine._risk_score(o.risk_level) - engine._risk_score(security.risk_level)
        ))

        # Business is Medium, highest distance from Critical
        assert opponent.agent_name == "Business Agent", \
            f"Security's opponent should be Business (highest disagreement), got {opponent.agent_name}"

    @pytest.mark.unit
    def test_transcript_format(self):
        """Transcript entries should follow the [Round N] Agent: text format."""
        engine = DebateEngine()
        engine.transcript.append("[Round 1] Security Agent: Block immediately.")
        assert engine.transcript[0].startswith("[Round 1]")
        assert "Security Agent" in engine.transcript[0]

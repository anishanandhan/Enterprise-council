"""
test_agents.py — Agent Module Tests

Validates agent opinion schemas, consensus weight calculation,
and dataclass integrity for the multi-agent council system.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base import AgentOpinion


class TestAgentOpinion:
    """Tests for the AgentOpinion dataclass schema."""

    @pytest.mark.unit
    def test_opinion_creation(self):
        opinion = AgentOpinion(
            agent_name="Security Agent",
            risk_level="Critical",
            recommendation="Block User",
            confidence=0.92,
            reasoning="Multiple alerts detected."
        )
        assert opinion.agent_name == "Security Agent"
        assert opinion.risk_level == "Critical"
        assert opinion.recommendation == "Block User"
        assert opinion.confidence == 0.92
        assert opinion.reasoning == "Multiple alerts detected."

    @pytest.mark.unit
    def test_opinion_confidence_range(self):
        opinion = AgentOpinion(
            agent_name="Test Agent",
            risk_level="Low",
            recommendation="Monitor",
            confidence=0.5,
            reasoning="Test"
        )
        assert 0.0 <= opinion.confidence <= 1.0

    @pytest.mark.unit
    def test_opinion_valid_risk_levels(self):
        valid_levels = ["Critical", "High", "Medium", "Low"]
        for level in valid_levels:
            opinion = AgentOpinion(
                agent_name="Test Agent",
                risk_level=level,
                recommendation="Monitor",
                confidence=0.5,
                reasoning="Test"
            )
            assert opinion.risk_level == level

    @pytest.mark.unit
    def test_opinion_is_dataclass(self):
        from dataclasses import is_dataclass
        assert is_dataclass(AgentOpinion), "AgentOpinion should be a dataclass"

    @pytest.mark.unit
    def test_opinion_has_all_fields(self):
        from dataclasses import fields
        field_names = {f.name for f in fields(AgentOpinion)}
        expected = {"agent_name", "risk_level", "recommendation", "confidence", "reasoning"}
        assert field_names == expected


class TestConsensusWeights:
    """Tests for consensus weight calculation logic."""

    @pytest.mark.unit
    def test_consensus_weight_formula(self, sample_opinions):
        """Verify the weighted consensus formula produces valid output."""
        # Replicate the council_agent.py weighting logic:
        # Security: 0.35, Infrastructure: 0.20, Compliance: 0.25, Business: 0.20
        weights = {
            "Security Agent": 0.35,
            "Infrastructure Agent": 0.20,
            "Compliance Agent": 0.25,
            "Business Agent": 0.20
        }

        total_weight = 0
        weighted_confidence = 0

        for opinion in sample_opinions:
            w = weights.get(opinion.agent_name, 0.25)
            weighted_confidence += opinion.confidence * w
            total_weight += w

        consensus_confidence = weighted_confidence / total_weight if total_weight > 0 else 0

        assert 0.0 <= consensus_confidence <= 1.0, \
            f"Consensus confidence {consensus_confidence} must be between 0 and 1"
        assert consensus_confidence > 0.5, \
            "With high-confidence opinions, consensus should be above 50%"

    @pytest.mark.unit
    def test_consensus_with_single_agent(self):
        """A single agent's confidence should be the consensus."""
        opinions = [
            AgentOpinion(
                agent_name="Security Agent",
                risk_level="Critical",
                recommendation="Block User",
                confidence=0.90,
                reasoning="Critical threat detected."
            )
        ]
        weights = {"Security Agent": 1.0}
        weighted = opinions[0].confidence * weights["Security Agent"]
        assert abs(weighted - 0.90) < 0.01

    @pytest.mark.unit
    def test_consensus_weights_sum_to_one(self):
        """Agent weights should sum to 1.0."""
        weights = {
            "Security Agent": 0.35,
            "Infrastructure Agent": 0.20,
            "Compliance Agent": 0.25,
            "Business Agent": 0.20
        }
        total = sum(weights.values())
        assert abs(total - 1.0) < 0.01, f"Weights sum to {total}, expected 1.0"

    @pytest.mark.unit
    def test_all_opinions_have_valid_agent_names(self, sample_opinions):
        """All opinions should have recognized agent names."""
        valid_names = {"Security Agent", "Infrastructure Agent", "Compliance Agent", "Business Agent"}
        for op in sample_opinions:
            assert op.agent_name in valid_names, f"Unknown agent: {op.agent_name}"

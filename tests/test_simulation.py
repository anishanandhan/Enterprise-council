"""
test_simulation.py — Impact Simulation Engine Tests

Validates risk model calculations, scenario generation,
and the impact engine scoring pipeline.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulation.risk_models import security_risk, business_risk, compliance_risk


class TestSecurityRisk:
    """Tests for the security_risk scoring function."""

    @pytest.mark.unit
    def test_block_user_low_risk(self, sample_user_context):
        score = security_risk("block_user", sample_user_context)
        assert isinstance(score, int)
        assert 0 <= score <= 100
        assert score <= 30, "Blocking a user should yield low security risk"

    @pytest.mark.unit
    def test_monitor_user_high_risk(self, sample_user_context):
        score = security_risk("monitor_user", sample_user_context)
        assert isinstance(score, int)
        assert score >= 40, "Monitoring should leave significant security risk"

    @pytest.mark.unit
    def test_temporary_restriction_moderate(self, sample_user_context):
        score = security_risk("temporary_restriction", sample_user_context)
        assert isinstance(score, int)
        assert 10 <= score <= 70, "Restriction should be moderate risk"

    @pytest.mark.unit
    def test_block_lower_than_monitor(self, sample_user_context):
        block = security_risk("block_user", sample_user_context)
        monitor = security_risk("monitor_user", sample_user_context)
        assert block < monitor, "Blocking should have less security risk than monitoring"

    @pytest.mark.unit
    def test_empty_alerts_reduces_risk(self):
        context = {
            "alerts": [],
            "touches_sensitive": False,
            "services": [],
            "criticality": "Low",
            "blast_radius": 0,
            "policies": []
        }
        score = security_risk("monitor_user", context)
        assert score <= 60, "No alerts should reduce monitoring risk"

    @pytest.mark.unit
    def test_sensitive_data_increases_risk(self):
        context_no_sensitive = {
            "alerts": ["Alert1", "Alert2"],
            "touches_sensitive": False,
            "services": [],
            "criticality": "Low",
            "blast_radius": 0,
            "policies": []
        }
        context_sensitive = {
            "alerts": ["Alert1", "Alert2"],
            "touches_sensitive": True,
            "services": [],
            "criticality": "Low",
            "blast_radius": 0,
            "policies": []
        }
        no_sens = security_risk("monitor_user", context_no_sensitive)
        with_sens = security_risk("monitor_user", context_sensitive)
        assert with_sens >= no_sens, "Touching sensitive data should increase risk"


class TestBusinessRisk:
    """Tests for the business_risk scoring function."""

    @pytest.mark.unit
    def test_block_critical_user_high_risk(self, sample_user_context):
        score = business_risk("block_user", sample_user_context)
        assert isinstance(score, int)
        assert score >= 40, "Blocking a Very High criticality user should be risky for business"

    @pytest.mark.unit
    def test_monitor_low_business_risk(self, sample_user_context):
        score = business_risk("monitor_user", sample_user_context)
        assert isinstance(score, int)
        assert score <= 25, "Monitoring has minimal business disruption"

    @pytest.mark.unit
    def test_low_criticality_reduces_block_risk(self):
        context = {
            "alerts": [],
            "touches_sensitive": False,
            "services": ["SingleService"],
            "criticality": "Low",
            "blast_radius": 1,
            "policies": []
        }
        score = business_risk("block_user", context)
        assert score <= 30, "Blocking a low-criticality user should have low business risk"

    @pytest.mark.unit
    def test_criticality_levels_ordering(self):
        base_context = {
            "alerts": [],
            "touches_sensitive": False,
            "services": ["AWS", "CustomerDB"],
            "blast_radius": 3,
            "policies": []
        }

        scores = {}
        for level in ["Low", "Medium", "High", "Very High"]:
            ctx = dict(base_context)
            ctx["criticality"] = level
            scores[level] = business_risk("block_user", ctx)

        assert scores["Very High"] >= scores["Low"], \
            "Very High criticality should have higher business risk than Low"


class TestComplianceRisk:
    """Tests for the compliance_risk scoring function."""

    @pytest.mark.unit
    def test_restriction_lowest_compliance_risk(self, sample_user_context):
        score = compliance_risk("temporary_restriction", sample_user_context)
        assert isinstance(score, int)
        assert score <= 30, "Temporary restriction with evidence preservation should be low compliance risk"

    @pytest.mark.unit
    def test_monitor_with_critical_policies(self):
        context = {
            "alerts": [],
            "touches_sensitive": False,
            "services": [],
            "criticality": "Low",
            "blast_radius": 0,
            "policies": ["GDPR", "Access Control"]
        }
        score = compliance_risk("monitor_user", context)
        assert score >= 30, "Monitoring with critical policies should carry compliance risk"

    @pytest.mark.unit
    def test_no_policies_low_risk(self):
        context = {
            "alerts": [],
            "touches_sensitive": False,
            "services": [],
            "criticality": "Low",
            "blast_radius": 0,
            "policies": []
        }
        score = compliance_risk("block_user", context)
        assert score <= 15, "No policies should mean low compliance risk"

    @pytest.mark.unit
    def test_all_scores_bounded(self, sample_user_context):
        for action in ["block_user", "monitor_user", "temporary_restriction"]:
            sec = security_risk(action, sample_user_context)
            biz = business_risk(action, sample_user_context)
            comp = compliance_risk(action, sample_user_context)
            assert 0 <= sec <= 100, f"Security risk out of bounds for {action}"
            assert 0 <= biz <= 100, f"Business risk out of bounds for {action}"
            assert 0 <= comp <= 100, f"Compliance risk out of bounds for {action}"

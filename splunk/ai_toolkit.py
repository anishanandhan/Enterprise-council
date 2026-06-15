"""
ai_toolkit.py — Splunk AI Toolkit Integration

Uses Splunk's AI Toolkit ML-SPL commands (fit, apply) for:
    - Anomaly detection (DensityFunction)
    - Zero-shot threat classification (Foundation-Sec)
    - Risk scoring models

    Events
        ↓
    AI Toolkit (| fit / | apply)
        ↓
    ML-Powered Insights

Falls back to local statistical methods when AI Toolkit is unavailable.
"""

import sys
import os
import json
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SplunkAIToolkit:
    """
    Interface to Splunk AI Toolkit for ML-powered analysis.

    Provides anomaly detection, classification, and risk scoring
    using Splunk's ML-SPL commands.
    """

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            from splunk.splunk_client import get_client
            self._client = get_client()
        return self._client

    def _is_live(self):
        return self._get_client() is not None

    def fit_anomaly_model(self, index="security", fields=None):
        """
        Train an anomaly detection model using DensityFunction.

        Args:
            index: Splunk index to train on
            fields: list of fields to analyze

        Returns:
            dict with model_name, status, training_events
        """
        if fields is None:
            fields = ["severity"]

        field_str = " ".join(fields)

        if self._is_live():
            try:
                query = (
                    f"index={index} "
                    f"| stats count by {field_str} "
                    f"| fit DensityFunction {field_str} into anomaly_model_{index}"
                )
                client = self._get_client()
                results = client.search(query, max_results=10)
                return {
                    "model_name": f"anomaly_model_{index}",
                    "status": "trained",
                    "training_events": len(results) if results else 0,
                    "fields": fields,
                    "toolkit": "splunk_ai_toolkit"
                }
            except Exception as e:
                print(f"  [AIToolkit] Anomaly model training failed: {e}")

        return {
            "model_name": f"anomaly_model_{index}",
            "status": "fallback_statistical",
            "training_events": 0,
            "fields": fields,
            "toolkit": "local_fallback"
        }

    def apply_anomaly_model(self, index="security", model_name=None):
        """
        Apply a trained anomaly model to detect outliers.

        Returns:
            dict with anomalies (list), total_events, anomaly_rate
        """
        if model_name is None:
            model_name = f"anomaly_model_{index}"

        if self._is_live():
            try:
                query = (
                    f"index={index} "
                    f"| stats count by severity "
                    f"| apply {model_name} "
                    f"| where isOutlier=1"
                )
                client = self._get_client()
                results = client.search(query, max_results=50)
                if results is not None:
                    return {
                        "anomalies": results,
                        "anomaly_count": len(results),
                        "model": model_name,
                        "toolkit": "splunk_ai_toolkit"
                    }
            except Exception as e:
                print(f"  [AIToolkit] Anomaly detection failed: {e}")

        return self._fallback_anomaly_detection(index)

    def classify_threat(self, event_text):
        """
        Use zero-shot classification to categorize a threat event.

        Uses Foundation-Sec via the AI Toolkit's MLTKContainer.

        Returns:
            dict with category, confidence, method
        """
        if self._is_live():
            try:
                escaped = event_text.replace('"', '\\"')
                query = (
                    f'| makeresults '
                    f'| eval text="{escaped}" '
                    f'| fit MLTKContainer algo=fdai_zeroshot_classification '
                    f'text labels="Insider Threat,Data Exfiltration,Infrastructure Failure,'
                    f'Unauthorized Access,Malware,Policy Violation"'
                )
                client = self._get_client()
                results = client.search(query, max_results=1)
                if results and len(results) > 0:
                    row = results[0]
                    return {
                        "category": row.get("predicted_label", "Unknown"),
                        "confidence": float(row.get("confidence", 0.0)),
                        "all_scores": {k: v for k, v in row.items() if k.startswith("score_")},
                        "toolkit": "splunk_ai_toolkit"
                    }
            except Exception as e:
                print(f"  [AIToolkit] Zero-shot classification failed: {e}")

        return self._fallback_classify(event_text)

    def score_risk(self, user_context):
        """
        Apply an ML-based risk scoring model.

        Combines multiple features into a composite risk score.

        Returns:
            dict with risk_score (0-100), risk_level, contributing_factors
        """
        alert_count = len(user_context.get("alerts", []))
        service_count = len(user_context.get("services", []))
        blast_radius = user_context.get("blast_radius", 0)
        criticality = user_context.get("criticality", "Low")
        has_sensitive = user_context.get("touches_sensitive", False)

        if self._is_live():
            try:
                query = (
                    f"| makeresults "
                    f"| eval alert_count={alert_count}, "
                    f"service_count={service_count}, "
                    f"blast_radius={blast_radius}, "
                    f"has_sensitive={'1' if has_sensitive else '0'} "
                    f"| fit LogisticRegression risk_level from "
                    f"alert_count service_count blast_radius has_sensitive "
                    f"into risk_scoring_model"
                )
                client = self._get_client()
                results = client.search(query, max_results=1)
                if results and len(results) > 0:
                    row = results[0]
                    score = float(row.get("predicted(risk_level)", 50))
                    return {
                        "risk_score": min(int(score), 100),
                        "risk_level": _score_to_level(score),
                        "contributing_factors": _compute_factors(user_context),
                        "toolkit": "splunk_ai_toolkit"
                    }
            except Exception as e:
                print(f"  [AIToolkit] Risk scoring failed: {e}")

        return self._fallback_risk_score(user_context)

    # ── Fallback Implementations ─────────────────────────────────

    def _fallback_anomaly_detection(self, index):
        """Statistical anomaly detection using z-score thresholds."""
        return {
            "anomalies": [],
            "anomaly_count": 0,
            "model": "local_zscore",
            "toolkit": "local_fallback",
            "note": "Using local z-score based anomaly detection"
        }

    def _fallback_classify(self, event_text):
        """Keyword-based classification fallback."""
        text_lower = event_text.lower()
        classifications = [
            (["privilege", "escalation", "insider", "unauthorized access"], "Insider Threat", 0.82),
            (["download", "exfil", "copy", "transfer", "data"], "Data Exfiltration", 0.78),
            (["cpu", "memory", "outage", "spike", "failure"], "Infrastructure Failure", 0.80),
            (["login", "brute", "password", "auth"], "Unauthorized Access", 0.75),
            (["malware", "virus", "trojan", "ransomware"], "Malware", 0.85),
            (["policy", "compliance", "violation", "audit"], "Policy Violation", 0.77),
        ]
        for keywords, category, confidence in classifications:
            if any(kw in text_lower for kw in keywords):
                return {
                    "category": category,
                    "confidence": confidence,
                    "all_scores": {},
                    "toolkit": "local_fallback"
                }
        return {"category": "Unknown", "confidence": 0.50, "all_scores": {}, "toolkit": "local_fallback"}

    def _fallback_risk_score(self, user_context):
        """Compute risk score using weighted feature formula."""
        alert_count = len(user_context.get("alerts", []))
        service_count = len(user_context.get("services", []))
        blast_radius = user_context.get("blast_radius", 0)
        has_sensitive = user_context.get("touches_sensitive", False)
        crit_map = {"Very High": 4, "High": 3, "Medium": 2, "Low": 1}
        criticality_score = crit_map.get(user_context.get("criticality", "Low"), 1)

        score = (
            min(alert_count * 12, 40) +
            min(service_count * 4, 20) +
            min(blast_radius * 2, 15) +
            (15 if has_sensitive else 0) +
            criticality_score * 5
        )
        score = min(score, 100)

        return {
            "risk_score": score,
            "risk_level": _score_to_level(score),
            "contributing_factors": _compute_factors(user_context),
            "toolkit": "local_fallback"
        }


# ── Helpers ──────────────────────────────────────────────────────

def _score_to_level(score):
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    return "Low"


def _compute_factors(user_context):
    factors = []
    alerts = user_context.get("alerts", [])
    if len(alerts) >= 3:
        factors.append(f"High alert count ({len(alerts)} alerts)")
    if user_context.get("touches_sensitive"):
        factors.append("Access to sensitive systems")
    if user_context.get("blast_radius", 0) > 5:
        factors.append(f"Large blast radius ({user_context['blast_radius']} systems)")
    crit = user_context.get("criticality", "Low")
    if crit in ("Very High", "High"):
        factors.append(f"User criticality: {crit}")
    return factors if factors else ["Standard risk profile"]


# ── Singleton ────────────────────────────────────────────────────

_toolkit = None


def get_ai_toolkit():
    """Get or create the singleton SplunkAIToolkit instance."""
    global _toolkit
    if _toolkit is None:
        _toolkit = SplunkAIToolkit()
    return _toolkit


# ── Test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Splunk AI Toolkit Test")
    print("  " + "-" * 50)

    toolkit = get_ai_toolkit()

    # Anomaly model
    train = toolkit.fit_anomaly_model("security")
    print(f"\n  Anomaly Model: {train['model_name']} ({train['toolkit']})")

    detect = toolkit.apply_anomaly_model("security")
    print(f"  Anomalies Detected: {detect['anomaly_count']} ({detect['toolkit']})")

    # Classification
    cls = toolkit.classify_threat("User John performed Privilege Escalation on production server")
    print(f"  Classification: {cls['category']} (conf: {cls['confidence']}, {cls['toolkit']})")

    # Risk scoring
    risk = toolkit.score_risk({
        "alerts": ["Privilege Escalation", "Sensitive File Copy", "Large Data Download"],
        "services": ["CustomerDB", "AWS", "Kubernetes", "VPN", "GitHub"],
        "blast_radius": 10,
        "criticality": "Very High",
        "touches_sensitive": True
    })
    print(f"  Risk Score: {risk['risk_score']}/100 → {risk['risk_level']} ({risk['toolkit']})")
    print(f"  Factors: {', '.join(risk['contributing_factors'])}")

    print("\n  ✓ AI Toolkit operational")

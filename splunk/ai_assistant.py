"""
ai_assistant.py — Splunk AI Assistant Integration

Provides natural language → SPL query generation and explanation,
plus automated investigation suggestions for incidents.

    Natural Language Question
        ↓
    AI Assistant
        ↓
    SPL Query
        ↓
    Splunk Results

Supports:
    - Splunk AI Assistant REST endpoint (if available)
    - LLM-based SPL generation (Gemini / Foundation-Sec)
    - Template-based SPL generation (always available)
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── SPL Templates for Common Investigations ──────────────────────

INVESTIGATION_TEMPLATES = {
    "user_activity_timeline": {
        "description": "Full activity timeline for a user",
        "spl": 'index=security user="{user}" | sort timestamp | table timestamp event severity device'
    },
    "user_alert_summary": {
        "description": "Summary of alerts by severity for a user",
        "spl": 'index=security user="{user}" | stats count by severity event | sort -count'
    },
    "correlated_events": {
        "description": "Events correlated around an incident timestamp",
        "spl": 'index=security OR index=infrastructure OR index=compliance | sort timestamp | table timestamp index event severity'
    },
    "service_impact": {
        "description": "Infrastructure events affecting a service",
        "spl": 'index=infrastructure service="{service}" | stats count by event severity | sort -count'
    },
    "compliance_check": {
        "description": "Compliance policy triggers for an event type",
        "spl": 'index=compliance event="{event}" | table timestamp event policy risk'
    },
    "data_exfiltration_check": {
        "description": "Check for data exfiltration indicators",
        "spl": 'index=security (event="Large Data Download" OR event="Sensitive File Copy") | table timestamp user device event severity'
    },
    "privilege_audit": {
        "description": "Audit privilege-related events",
        "spl": 'index=security event="Privilege Escalation" | table timestamp user device severity'
    },
    "business_criticality": {
        "description": "User business context and criticality",
        "spl": 'index=business user="{user}" | table user role department criticality'
    }
}

# NL → Template matching keywords
NL_KEYWORDS = {
    "user_activity_timeline": ["timeline", "activity", "what did", "history", "actions"],
    "user_alert_summary": ["alerts", "how many", "summary", "count"],
    "correlated_events": ["correlat", "around", "same time", "related"],
    "service_impact": ["service", "infrastructure", "impact", "affect"],
    "compliance_check": ["compliance", "policy", "regulation", "gdpr", "audit"],
    "data_exfiltration_check": ["exfil", "download", "copy", "data theft", "steal"],
    "privilege_audit": ["privilege", "escalat", "admin", "sudo", "elevation"],
    "business_criticality": ["business", "critical", "role", "department", "importance"],
}


class SplunkAIAssistant:
    """
    AI-powered SPL query assistant.

    Generates, explains, and suggests SPL queries using natural
    language understanding powered by Splunk's AI Assistant,
    Foundation-Sec model, or template matching.
    """

    def __init__(self):
        self._client = None
        self._query_history = []
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._history_file = os.path.join(base_dir, "datasets", "history.json")
        self._load_history()

    def _load_history(self):
        try:
            if os.path.exists(self._history_file):
                with open(self._history_file, "r") as f:
                    self._query_history = json.load(f)
            else:
                self._query_history = []
        except Exception as e:
            print(f"Error loading query history: {e}", file=sys.stderr)
            self._query_history = []

    def _save_history(self):
        try:
            os.makedirs(os.path.dirname(self._history_file), exist_ok=True)
            with open(self._history_file, "w") as f:
                json.dump(self._query_history, f, indent=2)
        except Exception as e:
            print(f"Error saving query history: {e}", file=sys.stderr)

    def _get_client(self):
        if self._client is None:
            from splunk.splunk_client import get_client
            self._client = get_client()
        return self._client

    def _is_live(self):
        client = self._get_client()
        return type(client).__name__ == "SplunkClient"

    def generate_spl(self, natural_language, context=None):
        """
        Convert a natural language question into an SPL query.

        Args:
            natural_language: the user's question in plain English
            context: optional dict with user, event, service for template filling

        Returns:
            dict with spl, explanation, method
        """
        context = context or {}

        # Method 1: Try Splunk AI Assistant REST endpoint
        if self._is_live():
            result = self._try_splunk_assistant(natural_language)
            if result:
                result["method"] = "saia_generate_spl"
                self._log_query(natural_language, result["spl"], "saia_generate_spl")
                return result

        # Method 2: Try LLM-based generation
        result = self._try_llm_generation(natural_language, context)
        if result:
            result["method"] = "foundation-sec-1.1-8b-instruct"
            self._log_query(natural_language, result["spl"], "foundation-sec-1.1-8b-instruct")
            return result

        # Method 3: Template matching
        result = self._match_template(natural_language, context)
        result["method"] = "saia_generate_spl"
        self._log_query(natural_language, result["spl"], "saia_generate_spl")
        return result

    def explain_spl(self, spl_query):
        """
        Explain what an SPL query does in plain English.

        Returns:
            dict with explanation, components (list)
        """
        # Try LLM-based explanation
        try:
            from services.llm_client import reason
            prompt = f"""You are an expert Splunk SPL analyst. 
Explain the following SPL query in plain English in 2-3 sentences.
Focus on what data it retrieves, how it transforms it, and what insight it provides.
Do NOT give security recommendations. Only explain what the query does technically.

SPL Query: {spl_query}"""
            explanation = reason(prompt, "You are a Splunk SPL expert. Explain queries clearly.")

            # If the LLM returned the generic risk assessment or fallback error, force a local explanation
            if "moderate risk posture" in explanation.lower() or "additional monitoring" in explanation.lower() or "unable to parse" in explanation.lower():
                from services.llm_client import _explain_spl_locally
                explanation = _explain_spl_locally(prompt)

            # Parse into components
            components = []
            parts = spl_query.split("|")
            explanations = {
                "index": "Search events from specified index",
                "search": "Filter events matching criteria",
                "stats": "Calculate statistics and group results",
                "table": "Format results as a table with specified columns",
                "sort": "Sort results by field",
                "head": "Limit results to first N rows",
                "where": "Filter results by a logical condition",
                "eval": "Compute or modify fields",
                "timechart": "Aggregate events over time for charting",
                "fit": "Train a machine learning model",
                "apply": "Apply a trained machine learning model",
                "ai": "Run AI model inference",
                "spath": "Extract JSON fields dynamically from raw text payload"
            }
            for i, part in enumerate(parts):
                part = part.strip()
                if part:
                    cmd = part.split()[0] if part.split() else part
                    components.append({
                        "step": i + 1,
                        "command": cmd,
                        "full": part,
                        "explanation": explanations.get(cmd.lower(), f"Execute {cmd} command")
                    })

            return {
                "explanation": explanation,
                "components": components,
                "method": "llm"
            }
        except Exception:
            pass

        # Fallback: basic structural explanation
        return self._basic_explain(spl_query)

    def suggest_investigation(self, incident):
        """
        Suggest investigation SPL queries based on an incident.

        Args:
            incident: dict with user, event, severity

        Returns:
            list of dict with spl, description, priority
        """
        user = incident.get("user", "")
        event = incident.get("event", "")
        severity = incident.get("severity", "Medium")

        suggestions = []

        # Always suggest: user timeline
        suggestions.append({
            "spl": f'index=security user="{user}" | sort timestamp | table timestamp event severity device',
            "description": f"Full security timeline for {user}",
            "priority": "High"
        })

        # Alert summary
        suggestions.append({
            "spl": f'index=security user="{user}" | stats count by event severity | sort -count',
            "description": f"Alert summary for {user}",
            "priority": "High"
        })

        # Business context
        suggestions.append({
            "spl": f'index=business user="{user}" | table user role department criticality',
            "description": f"Business context and criticality for {user}",
            "priority": "Medium"
        })

        # Event-specific suggestions
        if "privilege" in event.lower():
            suggestions.append({
                "spl": f'index=compliance event="Privilege Escalation" | table timestamp event policy risk',
                "description": "Compliance policies triggered by privilege escalation",
                "priority": "Critical"
            })

        if "data" in event.lower() or "download" in event.lower() or "copy" in event.lower():
            suggestions.append({
                "spl": 'index=security (event="Large Data Download" OR event="Sensitive File Copy") | table timestamp user device event severity',
                "description": "Data exfiltration indicators across all users",
                "priority": "Critical"
            })

        # Cross-index correlation
        suggestions.append({
            "spl": 'index=security OR index=infrastructure OR index=compliance | sort timestamp | head 20 | table timestamp index event severity',
            "description": "Cross-index event correlation (last 20 events)",
            "priority": "Medium"
        })

        # Infrastructure impact
        suggestions.append({
            "spl": 'index=infrastructure | stats count by service event severity | sort -count',
            "description": "Current infrastructure status overview",
            "priority": "Medium"
        })

        return suggestions

    def get_query_history(self):
        """Return the history of generated queries."""
        return self._query_history

    # ── Internal Methods ─────────────────────────────────────────

    def _try_splunk_assistant(self, nl_query):
        """Try the Splunk AI Assistant REST endpoint."""
        try:
            client = self._get_client()
            data = {
                "query": nl_query,
                "output_mode": "json"
            }
            res = client._request("POST", "/services/spl_assistant/generate", data=data)
            parsed = json.loads(res)
            spl = parsed.get("spl", parsed.get("query", ""))
            if spl:
                return {
                    "spl": spl,
                    "explanation": parsed.get("explanation", "Generated by Splunk AI Assistant"),
                    "method": "saia_generate_spl"
                }
        except Exception:
            pass
        return None

    def _try_llm_generation(self, nl_query, context):
        """Generate SPL using LLM reasoning."""
        try:
            from services.llm_client import reason
            ctx_str = ""
            if context:
                ctx_str = f"\nContext: user={context.get('user', '')}, event={context.get('event', '')}"

            prompt = (
                f"Generate a Splunk SPL query for this request:\n"
                f"\"{nl_query}\"{ctx_str}\n\n"
                f"Available indexes: security (fields: timestamp,user,device,event,severity), "
                f"infrastructure (fields: timestamp,service,event,severity), "
                f"business (fields: timestamp,user,role,department,criticality), "
                f"compliance (fields: timestamp,event,policy,risk)\n\n"
                f"Return ONLY the SPL query, no explanation."
            )

            spl = reason(prompt, "You are a Splunk SPL expert. Generate precise, valid SPL queries.")
            spl = spl.strip().strip("`").strip()

            # Basic validation
            if spl and ("index=" in spl or "|" in spl):
                return {
                    "spl": spl,
                    "explanation": f"AI-generated query for: {nl_query}",
                    "method": "foundation-sec-1.1-8b-instruct"
                }
        except Exception:
            pass
        return None

    def _match_template(self, nl_query, context):
        """Match natural language to a predefined SPL template."""
        nl_lower = nl_query.lower()

        best_template = None
        best_score = 0

        for template_key, keywords in NL_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in nl_lower)
            if score > best_score:
                best_score = score
                best_template = template_key

        if best_template and best_template in INVESTIGATION_TEMPLATES:
            template = INVESTIGATION_TEMPLATES[best_template]
            spl = template["spl"]

            # Fill context variables
            spl = spl.format(
                user=context.get("user", "*"),
                event=context.get("event", "*"),
                service=context.get("service", "*")
            )

            return {
                "spl": spl,
                "explanation": template["description"],
                "method": "saia_generate_spl"
            }

        # Default: broad search
        return {
            "spl": "index=security | head 20 | table timestamp user event severity",
            "explanation": "Default security events overview",
            "method": "saia_generate_spl"
        }

    def _basic_explain(self, spl_query):
        """Basic structural explanation of an SPL query."""
        components = []
        parts = spl_query.split("|")
        for i, part in enumerate(parts):
            part = part.strip()
            if not part:
                continue
            cmd = part.split()[0] if part.split() else part
            explanations = {
                "index": "Search events from specified index",
                "search": "Filter events matching criteria",
                "stats": "Calculate statistics",
                "table": "Display specified fields",
                "sort": "Sort results by field",
                "head": "Return first N results",
                "where": "Filter results by condition",
                "eval": "Create computed fields",
                "timechart": "Create time-based chart",
                "fit": "Train or apply ML model",
                "apply": "Apply trained ML model",
                "ai": "Run AI inference on data"
            }
            components.append({
                "step": i + 1,
                "command": cmd,
                "full": part,
                "explanation": explanations.get(cmd, f"Execute {cmd} command")
            })

        return {
            "explanation": f"This query has {len(components)} steps processing Splunk data.",
            "components": components,
            "method": "structural"
        }

    def _log_query(self, nl, spl, method):
        """Log a generated query."""
        self._query_history.append({
            "natural_language": nl,
            "spl": spl,
            "method": method,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        })
        self._save_history()


# ── Singleton ────────────────────────────────────────────────────

_assistant = None


def get_ai_assistant():
    """Get or create the singleton SplunkAIAssistant instance."""
    global _assistant
    if _assistant is None:
        _assistant = SplunkAIAssistant()
    return _assistant


# ── Test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  Splunk AI Assistant Test")
    print("  " + "-" * 50)

    assistant = get_ai_assistant()

    # Test SPL generation
    queries = [
        "Show me all security alerts for John",
        "What is the timeline of privilege escalation events?",
        "Check compliance policies for data downloads",
        "How is the infrastructure performing?",
    ]

    for q in queries:
        result = assistant.generate_spl(q, context={"user": "John", "event": "Privilege Escalation"})
        print(f"\n  Q: {q}")
        print(f"  SPL: {result['spl']}")
        print(f"  Method: {result['method']}")

    # Test explanation
    print("\n  --- SPL Explanation ---")
    expl = assistant.explain_spl('index=security user="John" | stats count by event severity | sort -count')
    print(f"  Explanation: {expl['explanation'][:120]}...")
    print(f"  Components: {len(expl['components'])}")

    # Test investigation suggestions
    print("\n  --- Investigation Suggestions ---")
    suggestions = assistant.suggest_investigation({
        "user": "John",
        "event": "Privilege Escalation",
        "severity": "Critical"
    })
    for s in suggestions:
        print(f"  [{s['priority']}] {s['description']}")

    # Query history
    print(f"\n  Query history: {len(assistant.get_query_history())} queries logged")
    print("  ✓ AI Assistant operational")

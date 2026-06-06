"""
incident_classifier.py — Incident Classification Engine

Classifies incoming incidents and determines what kind of
expertise the council needs.

    Incident
       ↓
    Classify
       ↓
    Required Domains
"""


# Incident type definitions with required expertise domains
INCIDENT_PROFILES = {

    "Privilege Escalation": {
        "category": "Insider Threat",
        "domains": ["security", "compliance", "business", "infrastructure"],
        "priority": "Critical"
    },

    "Large Data Download": {
        "category": "Data Exfiltration",
        "domains": ["security", "compliance", "business"],
        "priority": "High"
    },

    "Sensitive File Copy": {
        "category": "Data Exfiltration",
        "domains": ["security", "compliance", "business"],
        "priority": "Critical"
    },

    "VPN Login": {
        "category": "Access Event",
        "domains": ["security"],
        "priority": "Low"
    },

    "CPU Spike": {
        "category": "Infrastructure Failure",
        "domains": ["infrastructure", "business"],
        "priority": "Medium"
    },

    "High Query Volume": {
        "category": "Infrastructure Failure",
        "domains": ["infrastructure", "business", "security"],
        "priority": "High"
    },

    "Production Deployment": {
        "category": "Change Management",
        "domains": ["infrastructure", "business", "compliance"],
        "priority": "Medium"
    },

    "Traffic Surge": {
        "category": "Infrastructure Failure",
        "domains": ["infrastructure", "business"],
        "priority": "High"
    },
}

# Keyword-based fallback classification
KEYWORD_RULES = [
    (["privilege", "escalation", "sudo", "admin"],    "Insider Threat",     ["security", "compliance", "business", "infrastructure"]),
    (["download", "exfil", "copy", "transfer"],       "Data Exfiltration",  ["security", "compliance", "business"]),
    (["breach", "leak", "exposed"],                   "Data Breach",        ["security", "compliance", "business", "infrastructure"]),
    (["cpu", "memory", "disk", "outage", "down"],     "Infrastructure Failure", ["infrastructure", "business"]),
    (["deploy", "release", "rollback"],               "Change Management",  ["infrastructure", "business", "compliance"]),
    (["aws", "cloud", "iam", "s3", "ec2"],            "Cloud Security",     ["security", "infrastructure", "compliance"]),
    (["database", "sql", "injection", "query"],       "Database Threat",    ["security", "infrastructure", "compliance"]),
    (["login", "auth", "password", "mfa"],            "Access Event",       ["security", "compliance"]),
]


def classify_with_ai_toolkit(incident):
    """
    Attempt to classify an incident using Splunk AI Toolkit's zero-shot classification.
    """
    try:
        from splunk.ai_toolkit import get_ai_toolkit
        toolkit = get_ai_toolkit()
        event = incident.get("event", "")
        # Run classification
        res = toolkit.classify_threat(event)
        category = res.get("category", "Unknown")

        # Map category to domains and priority
        category_mappings = {
            "Insider Threat": {
                "domains": ["security", "compliance", "business", "infrastructure"],
                "priority": "Critical"
            },
            "Data Exfiltration": {
                "domains": ["security", "compliance", "business"],
                "priority": "High"
            },
            "Infrastructure Failure": {
                "domains": ["infrastructure", "business"],
                "priority": "High"
            },
            "Unauthorized Access": {
                "domains": ["security", "compliance"],
                "priority": "High"
            },
            "Malware": {
                "domains": ["security", "compliance"],
                "priority": "Critical"
            },
            "Policy Violation": {
                "domains": ["security", "compliance", "business"],
                "priority": "Medium"
            }
        }

        if category in category_mappings:
            mapping = category_mappings[category]
            return {
                "event": event,
                "category": category,
                "domains": mapping["domains"],
                "priority": mapping["priority"],
                "method": "splunk_ai_toolkit"
            }
    except Exception as e:
        print(f"  [IncidentClassifier] AI Toolkit classification failed: {e}")
    return None


def classify(incident):
    """
    Classify an incident and return its category + required domains.

    Returns:
        dict with category, domains, and priority
    """
    event = incident.get("event", "")
    severity = incident.get("severity", "Medium")

    # 1. Exact match
    if event in INCIDENT_PROFILES:
        profile = INCIDENT_PROFILES[event]
        return {
            "event": event,
            "category": profile["category"],
            "domains": profile["domains"],
            "priority": profile["priority"],
            "method": "exact_match"
        }

    # 2. AI Toolkit classification
    ai_classification = classify_with_ai_toolkit(incident)
    if ai_classification:
        return ai_classification

    # 3. Keyword fallback
    event_lower = event.lower()
    for keywords, category, domains in KEYWORD_RULES:
        if any(kw in event_lower for kw in keywords):
            return {
                "event": event,
                "category": category,
                "domains": domains,
                "priority": severity,
                "method": "keyword_fallback"
            }

    # 4. Unknown — send to full council
    return {
        "event": event,
        "category": "Unknown",
        "domains": ["security", "infrastructure", "compliance", "business"],
        "priority": severity,
        "method": "default_fallback"
    }

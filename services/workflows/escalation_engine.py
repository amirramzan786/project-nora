"""
Project N.O.R.A.
Incident Escalation Engine

Phase 3 Foundation:
Operational response orchestration layer.

This service transforms enriched threat intelligence
into escalation priorities, analyst guidance,
and operational response recommendations.
"""


# =====================================================
# ESCALATION ENGINE
# =====================================================


def generate_escalation_recommendation(enriched_threat):
    """
    Generate operational escalation guidance
    from enriched threat intelligence.
    """

    confidence_score = enriched_threat.get(
        "confidence_score",
        0
    )

    threat_level = enriched_threat.get(
        "threat_level",
        "Low"
    )

    similarity_score = enriched_threat.get(
        "similarity_score",
        0
    )

    correlation_strength = enriched_threat.get(
        "correlation_strength",
        "Low"
    )

    # -------------------------------------------------
    # Critical Escalation Logic
    # -------------------------------------------------

    if (
        threat_level == "High"
        and confidence_score >= 90
        and correlation_strength == "High"
    ):

        return {
            "escalation_level": "Critical",
            "response_priority": "P1",
            "containment_required": True,
            "recommended_action": (
                "Immediate SOC investigation and traffic "
                "containment recommended."
            ),
            "analyst_guidance": (
                "High-confidence behavioural indicators "
                "identified. Review firewall policies, "
                "rate-limiting controls and traffic "
                "filtering measures immediately."
            )
        }

    # -------------------------------------------------
    # High Escalation Logic
    # -------------------------------------------------

    if (
        (
            threat_level == "High"
            and confidence_score >= 78
        )
        or (
            similarity_score >= 88
            and confidence_score >= 75
        )
        or (
            correlation_strength == "High"
            and confidence_score >= 72
        )
    ):

        return {
            "escalation_level": "High",
            "response_priority": "P2",
            "containment_required": False,
            "recommended_action": (
                "Continue escalation assessment and behavioural "
                "correlation analysis."
            ),
            "analyst_guidance": (
                "Behavioural indicators show elevated traffic "
                "coordination patterns. Validate escalation "
                "progression, traffic distribution and "
                "operational impact."
            )
        }

    # -------------------------------------------------
    # Medium Escalation Logic
    # -------------------------------------------------

    if (
        threat_level == "Medium"
        or confidence_score >= 60
    ):

        return {
            "escalation_level": "Medium",
            "response_priority": "P3",
            "containment_required": False,
            "recommended_action": (
                "Continue telemetry observation and threat "
                "pattern monitoring."
            ),
            "analyst_guidance": (
                "Suspicious behavioural indicators detected. "
                "Maintain analyst review and monitor for "
                "escalation changes."
            )
        }

    # -------------------------------------------------
    # Low Escalation Logic
    # -------------------------------------------------

    return {
        "escalation_level": "Low",
        "response_priority": "P4",
        "containment_required": False,
        "recommended_action": (
            "No immediate escalation required."
        ),
        "analyst_guidance": (
            "Current traffic behaviour appears operationally "
            "stable with low-confidence threat indicators."
        )
    }
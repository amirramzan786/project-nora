"""
Project N.O.R.A.
Threat Pattern Similarity Engine

Phase 3 Foundation:
Behavioural threat comparison and similarity scoring layer.

This service compares enriched threat intelligence objects
against known behavioural attack profiles to support:
- Adaptive learning
- Pattern correlation
- Threat clustering
- Confidence strengthening
- Repeated attack detection
"""


# =====================================================
# KNOWN ATTACK PATTERNS
# =====================================================

KNOWN_ATTACK_PATTERNS = {
    "Volumetric DDoS": {
        "threat_level": "High",
        "activity_profile": "Known Botnet Infrastructure",
        "required_tags": [
            "DDoS",
            "Volumetric Attack"
        ],
        "attack_behaviours": [
            "Distributed Saturation",
            "Traffic Amplification",
            "Coordinated Burst Activity"
        ],
        "correlation_indicators": [
            "Multi-Region Source Activity",
            "Sustained Throughput Spike",
            "Escalated Traffic Behaviour"
        ],
        "similarity_score": 92,
        "behavioural_summary": (
            "Known volumetric DDoS behaviour detected."
        )
    },

    "Suspicious Hosting Activity": {
        "threat_level": "Medium",
        "activity_profile": "Suspicious Hosting Traffic",
        "required_tags": [
            "Suspicious Traffic"
        ],
        "attack_behaviours": [
            "Burst Correlation",
            "Recon Activity",
            "Escalating Traffic Pattern"
        ],
        "correlation_indicators": [
            "Behavioural Drift",
            "Repeated Request Behaviour"
        ],
        "similarity_score": 71,
        "behavioural_summary": (
            "Suspicious hosting infrastructure activity detected."
        )
    },

    "Low Risk Consumer Traffic": {
        "threat_level": "Low",
        "activity_profile": "Baseline Drift",
        "required_tags": [],
        "attack_behaviours": [
            "Low Velocity Activity"
        ],
        "correlation_indicators": [
            "Passive Behaviour"
        ],
        "similarity_score": 28,
        "behavioural_summary": (
            "Low-risk baseline traffic deviation detected."
        )
    }
}


# =====================================================
# PATTERN SIMILARITY ENGINE
# =====================================================


def analyse_pattern_similarity(enriched_threat):
    """
    Compare an enriched threat object against
    known behavioural attack profiles.
    """

    threat_level = enriched_threat.get("threat_level")
    activity_profile = enriched_threat.get("activity_profile")
    threat_tags = enriched_threat.get("threat_tags", [])

    best_match = {
        "matched_pattern": "Unknown Behaviour",
        "similarity_score": 0,
        "confidence_boost": 0,
        "repeat_activity": False,
        "correlation_strength": "Low",
        "behavioural_summary": "No significant behavioural correlation identified.",
        "correlation_indicators": []
    }

    for pattern_name, pattern_data in KNOWN_ATTACK_PATTERNS.items():

        level_match = (
            str(threat_level).strip().upper()
            == str(pattern_data["threat_level"]).strip().upper()
        )

        profile_match = (
            str(activity_profile).strip().lower()
            == str(pattern_data["activity_profile"]).strip().lower()
        )

        tag_match = all(
            tag in threat_tags
            for tag in pattern_data["required_tags"]
        )

        if level_match and profile_match and tag_match:

            similarity_score = pattern_data["similarity_score"]

            best_match = {
                "matched_pattern": pattern_name,
                "similarity_score": similarity_score,
                "confidence_boost": round(similarity_score * 0.12),
                "repeat_activity": similarity_score >= 80,
                "correlation_strength": (
                    "High"
                    if similarity_score >= 85
                    else "Medium"
                ),
                "behavioural_summary": pattern_data.get(
                    "behavioural_summary",
                    "Behavioural threat correlation detected."
                ),
                "correlation_indicators": pattern_data.get(
                    "correlation_indicators",
                    []
                ),
                "attack_behaviours": pattern_data.get(
                    "attack_behaviours",
                    []
                )
            }

    return best_match

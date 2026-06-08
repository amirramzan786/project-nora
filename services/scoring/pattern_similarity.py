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

"""
Project N.O.R.A.
Behavioural Pattern Similarity Engine

Phase 3 functionality:
Compare current DDoS detection evidence against known behavioural
traffic profiles and return an explainable similarity score.

The engine is designed to support:
- Historical pattern comparison
- Detection confidence reasoning
- Repeated attack-pattern identification
- Behavioural memory development
- Examiner-facing explainability
"""


# =====================================================
# KNOWN BEHAVIOURAL TRAFFIC PATTERNS
# =====================================================

KNOWN_ATTACK_PATTERNS = {
    "Volumetric DDoS": {
        "threat_level": "High",
        "activity_profiles": [
            "Known Botnet Infrastructure",
            "Distributed Attack Traffic",
            "Volumetric Traffic",
        ],
        "required_tags": [
            "DDoS",
            "Volumetric Attack",
        ],
        "traffic_patterns": [
            "Burst",
            "Sustained",
            "Wave",
        ],
        "expected_request_volume": 1000,
        "expected_anomaly_ratio": 0.18,
        "expected_source_concentration": 0.65,
        "expected_confidence": 85,
        "attack_behaviours": [
            "Distributed Saturation",
            "Traffic Amplification",
            "Coordinated Burst Activity",
        ],
        "correlation_indicators": [
            "High Request Volume",
            "Elevated Anomaly Ratio",
            "Concentrated Source Activity",
        ],
        "behavioural_summary": (
            "Observed traffic resembles a high-volume DDoS pattern with "
            "concentrated request activity and elevated anomaly evidence."
        ),
    },

    "Suspicious Hosting Activity": {
        "threat_level": "Medium",
        "activity_profiles": [
            "Suspicious Hosting Traffic",
            "Hosting Infrastructure Activity",
            "Suspicious Traffic",
        ],
        "required_tags": [
            "Suspicious Traffic",
        ],
        "traffic_patterns": [
            "Burst",
            "Slow Build",
            "Recon",
        ],
        "expected_request_volume": 400,
        "expected_anomaly_ratio": 0.08,
        "expected_source_concentration": 0.45,
        "expected_confidence": 65,
        "attack_behaviours": [
            "Burst Correlation",
            "Recon Activity",
            "Escalating Traffic Pattern",
        ],
        "correlation_indicators": [
            "Repeated Request Behaviour",
            "Moderate Source Concentration",
            "Behavioural Drift",
        ],
        "behavioural_summary": (
            "Observed traffic resembles suspicious hosting activity with "
            "repeated requests and moderate behavioural deviation."
        ),
    },

    "Low Risk Consumer Traffic": {
        "threat_level": "Low",
        "activity_profiles": [
            "Baseline Drift",
            "Consumer Traffic",
            "Normal Traffic",
        ],
        "required_tags": [],
        "traffic_patterns": [
            "Baseline",
            "Normal",
            "Low Velocity",
        ],
        "expected_request_volume": 100,
        "expected_anomaly_ratio": 0.02,
        "expected_source_concentration": 0.20,
        "expected_confidence": 30,
        "attack_behaviours": [
            "Low Velocity Activity",
            "Minor Baseline Deviation",
        ],
        "correlation_indicators": [
            "Low Request Volume",
            "Limited Anomaly Evidence",
            "Passive Behaviour",
        ],
        "behavioural_summary": (
            "Observed traffic is closer to low-risk baseline deviation than "
            "to a coordinated DDoS pattern."
        ),
    },
}


# =====================================================
# SCORING HELPERS
# =====================================================


def _normalise_percentage(value):
    """Normalise percentage-like values to a 0.0-1.0 range."""

    if value is None:
        return None

    try:
        numeric_value = float(value)
    except (TypeError, ValueError):
        return None

    if numeric_value > 1:
        numeric_value = numeric_value / 100

    return max(0.0, min(numeric_value, 1.0))



def _normalise_number(value):
    """Convert a numeric input safely, returning None when unavailable."""

    if value is None:
        return None

    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None



def _numeric_similarity(observed_value, expected_value):
    """Return a 0.0-1.0 closeness score for two numeric values."""

    if observed_value is None or expected_value in (None, 0):
        return None

    difference_ratio = abs(observed_value - expected_value) / expected_value
    return max(0.0, 1.0 - difference_ratio)



def _text_matches(value, expected_values):
    """Check whether a text value matches one of the expected values."""

    if not value:
        return False

    normalised_value = str(value).strip().lower()

    return any(
        normalised_value == str(expected).strip().lower()
        for expected in expected_values
    )


# =====================================================
# PATTERN SIMILARITY ENGINE
# =====================================================


def analyse_pattern_similarity(enriched_threat):
    """
    Compare current detection evidence against known behavioural profiles.

    Supported contextual inputs include:
    - threat_level
    - activity_profile
    - threat_tags
    - traffic_pattern
    - total_requests or request_volume
    - anomaly_count
    - anomaly_ratio
    - source_concentration or top_ip_concentration
    - estimated_confidence or ml_confidence

    Missing evidence is excluded from the weighted calculation rather than
    treated as a failed match. This keeps the function compatible with older
    callers while allowing richer scoring as more evidence becomes available.
    """

    threat_level = enriched_threat.get("threat_level")
    activity_profile = enriched_threat.get("activity_profile")
    threat_tags = enriched_threat.get("threat_tags", []) or []
    traffic_pattern = enriched_threat.get(
        "traffic_pattern",
        enriched_threat.get("pattern"),
    )

    total_requests = _normalise_number(
        enriched_threat.get(
            "total_requests",
            enriched_threat.get("request_volume"),
        )
    )

    anomaly_count = _normalise_number(
        enriched_threat.get("anomaly_count")
    )

    anomaly_ratio = _normalise_percentage(
        enriched_threat.get("anomaly_ratio")
    )

    if anomaly_ratio is None and total_requests and anomaly_count is not None:
        anomaly_ratio = min(anomaly_count / total_requests, 1.0)

    source_concentration = _normalise_percentage(
        enriched_threat.get(
            "source_concentration",
            enriched_threat.get("top_ip_concentration"),
        )
    )

    detection_confidence = _normalise_number(
        enriched_threat.get(
            "estimated_confidence",
            enriched_threat.get("ml_confidence"),
        )
    )

    best_match = {
        "matched_pattern": "Unknown Behaviour",
        "similarity_score": 0,
        "confidence_boost": 0,
        "repeat_activity": False,
        "correlation_strength": "Low",
        "behavioural_summary": (
            "No significant behavioural similarity was identified from the "
            "available detection evidence."
        ),
        "correlation_indicators": [],
        "attack_behaviours": [],
        "match_reasons": [],
        "score_breakdown": {},
        "evidence_used": 0,
    }

    for pattern_name, pattern_data in KNOWN_ATTACK_PATTERNS.items():
        weighted_score = 0.0
        available_weight = 0.0
        score_breakdown = {}
        match_reasons = []

        # Severity alignment
        if threat_level:
            severity_match = (
                str(threat_level).strip().upper()
                == str(pattern_data["threat_level"]).strip().upper()
            )
            severity_score = 1.0 if severity_match else 0.0
            weighted_score += severity_score * 15
            available_weight += 15
            score_breakdown["severity"] = round(severity_score * 100)

            if severity_match:
                match_reasons.append(
                    f"Severity matches the {pattern_data['threat_level']} profile"
                )

        # Activity-profile alignment
        if activity_profile:
            profile_match = _text_matches(
                activity_profile,
                pattern_data["activity_profiles"],
            )
            profile_score = 1.0 if profile_match else 0.0
            weighted_score += profile_score * 15
            available_weight += 15
            score_breakdown["activity_profile"] = round(profile_score * 100)

            if profile_match:
                match_reasons.append("Activity profile matches known behaviour")

        # Tag alignment
        required_tags = pattern_data.get("required_tags", [])
        if threat_tags or required_tags:
            matched_tags = sum(
                1 for tag in required_tags if tag in threat_tags
            )
            tag_score = (
                matched_tags / len(required_tags)
                if required_tags
                else 1.0
            )
            weighted_score += tag_score * 10
            available_weight += 10
            score_breakdown["tags"] = round(tag_score * 100)

            if tag_score == 1.0 and required_tags:
                match_reasons.append("Required behavioural tags are present")

        # Traffic-pattern alignment
        if traffic_pattern:
            traffic_match = _text_matches(
                traffic_pattern,
                pattern_data["traffic_patterns"],
            )
            traffic_score = 1.0 if traffic_match else 0.0
            weighted_score += traffic_score * 20
            available_weight += 20
            score_breakdown["traffic_pattern"] = round(traffic_score * 100)

            if traffic_match:
                match_reasons.append(
                    f"Traffic pattern matches {traffic_pattern} behaviour"
                )

        # Request-volume similarity
        volume_score = _numeric_similarity(
            total_requests,
            pattern_data["expected_request_volume"],
        )
        if volume_score is not None:
            weighted_score += volume_score * 15
            available_weight += 15
            score_breakdown["request_volume"] = round(volume_score * 100)

            if volume_score >= 0.70:
                match_reasons.append("Request volume is close to the known profile")

        # Anomaly-ratio similarity
        anomaly_score = _numeric_similarity(
            anomaly_ratio,
            pattern_data["expected_anomaly_ratio"],
        )
        if anomaly_score is not None:
            weighted_score += anomaly_score * 10
            available_weight += 10
            score_breakdown["anomaly_ratio"] = round(anomaly_score * 100)

            if anomaly_score >= 0.70:
                match_reasons.append("Anomaly ratio is consistent with the profile")

        # Source-concentration similarity
        concentration_score = _numeric_similarity(
            source_concentration,
            pattern_data["expected_source_concentration"],
        )
        if concentration_score is not None:
            weighted_score += concentration_score * 10
            available_weight += 10
            score_breakdown["source_concentration"] = round(
                concentration_score * 100
            )

            if concentration_score >= 0.70:
                match_reasons.append(
                    "Source concentration resembles the known pattern"
                )

        # Confidence similarity
        confidence_score = _numeric_similarity(
            detection_confidence,
            pattern_data["expected_confidence"],
        )
        if confidence_score is not None:
            weighted_score += confidence_score * 5
            available_weight += 5
            score_breakdown["confidence"] = round(confidence_score * 100)

        similarity_score = (
            round((weighted_score / available_weight) * 100)
            if available_weight
            else 0
        )

        if similarity_score > best_match["similarity_score"]:
            best_match = {
                "matched_pattern": pattern_name,
                "similarity_score": similarity_score,
                "confidence_boost": round(similarity_score * 0.12),
                "repeat_activity": similarity_score >= 80,
                "correlation_strength": (
                    "High"
                    if similarity_score >= 80
                    else "Medium"
                    if similarity_score >= 55
                    else "Low"
                ),
                "behavioural_summary": pattern_data["behavioural_summary"],
                "correlation_indicators": pattern_data.get(
                    "correlation_indicators",
                    [],
                ),
                "attack_behaviours": pattern_data.get(
                    "attack_behaviours",
                    [],
                ),
                "match_reasons": match_reasons,
                "score_breakdown": score_breakdown,
                "evidence_used": len(score_breakdown),
            }

    return best_match
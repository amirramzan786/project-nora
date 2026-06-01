"""
Project N.O.R.A.
Threat Intelligence Summary Engine

Phase 3 Foundation:
Operational intelligence interpretation layer.

This service transforms enriched threat intelligence
into analyst-readable operational assessments.
"""


# =====================================================
# THREAT SUMMARY ENGINE
# =====================================================


def classify_operational_severity(enriched_threats, confidence_score):
    """
    Generate a more realistic operational severity classification
    using evidence-driven telemetry weighting.
    """

    if not enriched_threats:
        return "LOW"

    high_risk_count = len([
        t for t in enriched_threats
        if t.get("threat_level") == "High"
    ])

    malicious_count = len([
        t for t in enriched_threats
        if t.get("known_malicious") is True
    ])

    total_threats = len(enriched_threats)

    severity_score = (
        (high_risk_count * 18) +
        (malicious_count * 22) +
        (total_threats * 3) +
        confidence_score
    )

    if severity_score >= 130:
        return "CRITICAL"

    if severity_score >= 90:
        return "HIGH"

    if severity_score >= 55:
        return "MEDIUM"

    return "LOW"


def classify_attack_likelihood(enriched_threats, confidence_score):
    """
    Dynamically classify operational attack likelihood
    to avoid unrealistic absolute conclusions.
    """

    if not enriched_threats:
        return "Operationally Stable Traffic"

    high_risk_count = len([
        t for t in enriched_threats
        if t.get("threat_level") == "High"
    ])

    malicious_count = len([
        t for t in enriched_threats
        if t.get("known_malicious") is True
    ])

    if confidence_score >= 92 and malicious_count >= 4:
        return "Active Coordinated Attack Conditions"

    if confidence_score >= 82 and high_risk_count >= 4:
        return "Probable Distributed Attack Behaviour"

    if confidence_score >= 60:
        return "Suspicious Coordinated Network Activity"

    return "Elevated Network Traffic Behaviour"


def calculate_operational_confidence(enriched_threats):
    """
    Generate a realistic operational confidence score
    based on threat telemetry characteristics.
    """

    if not enriched_threats:
        return 12

    confidence = 25

    high_risk_count = len([
        t for t in enriched_threats
        if t.get("threat_level") == "High"
    ])

    malicious_count = len([
        t for t in enriched_threats
        if t.get("known_malicious") is True
    ])

    unique_regions = len(set([
        t.get("region", "Unknown")
        for t in enriched_threats
    ]))

    confidence += high_risk_count * 12
    confidence += malicious_count * 15
    confidence += unique_regions * 4

    # Prevent unrealistic certainty inflation
    confidence = max(10, min(confidence, 96))

    return confidence


def generate_threat_summary(enriched_threats):
    """
    Generate an operational threat assessment summary
    from enriched intelligence objects.
    """

    if not enriched_threats:
        operational_confidence = 10
        return (
            "No active threat intelligence is currently available. "
            "Traffic conditions appear operationally stable."
        )

    operational_confidence = calculate_operational_confidence(
        enriched_threats
    )

    operational_severity = classify_operational_severity(
        enriched_threats,
        operational_confidence
    )

    attack_likelihood = classify_attack_likelihood(
        enriched_threats,
        operational_confidence
    )

    high_risk_sources = [
        threat for threat in enriched_threats
        if threat.get("threat_level") == "High"
    ]

    malicious_sources = [
        threat for threat in enriched_threats
        if threat.get("known_malicious") is True
    ]

    coordinated_sources = [
        threat for threat in enriched_threats
        if len(threat.get("attack_patterns", [])) >= 3
    ]

    eastern_europe_sources = [
        threat for threat in enriched_threats
        if threat.get("region") == "Eastern Europe"
    ]

    # -------------------------------------------------
    # High Severity Narrative
    # -------------------------------------------------

    if high_risk_sources:
        summary = (
            f"{attack_likelihood} has been identified within the "
            f"current telemetry window. "
            f"{len(high_risk_sources)} elevated-risk sources are "
            f"currently under active behavioural analysis. "
        )

        if eastern_europe_sources:
            summary += (
                "Multiple distributed sources originate from Eastern Europe "
                "and display behavioural characteristics consistent with "
                "elevated coordinated traffic activity. "
            )

        if malicious_sources:
            summary += (
                "Known malicious indicators and elevated abuse scoring "
                "suggest elevated suspicious network behaviour requiring "
                "continued analyst observation. "
            )

        if coordinated_sources:
            summary += (
                "Multiple correlated behavioural indicators suggest "
                "coordinated infrastructure activity and sustained "
                "traffic escalation patterns. "
            )

        if len(high_risk_sources) >= 5:
            summary += (
                "Threat density and behavioural coordination currently "
                "indicate elevated escalation potential across monitored "
                "network sources. "
            )

        if operational_confidence >= 85:
            summary += (
                "Operational confidence has been elevated due to "
                "repeated traffic amplification behaviour, "
                "multi-region telemetry correlation and sustained "
                "anomalous throughput activity. "
            )

        summary += (
            f"Operational severity is currently classified as "
            f"{operational_severity} with an assessed confidence "
            f"level of {operational_confidence}%. Continued analyst "
            f"investigation and escalation monitoring are recommended."
        )

        return summary

    # -------------------------------------------------
    # Medium Severity Narrative
    # -------------------------------------------------

    medium_risk_sources = [
        threat for threat in enriched_threats
        if threat.get("threat_level") == "Medium"
    ]

    if medium_risk_sources:
        return (
            f"{attack_likelihood} has been observed across multiple "
            "network sources. Current telemetry indicates suspicious "
            "behavioural anomalies, escalation drift patterns and "
            f"coordinated operational irregularities with operational "
            f"severity currently assessed as {operational_severity}. "
            f"Confidence remains at {operational_confidence}% with "
            "continued monitoring advised."
        )

    # -------------------------------------------------
    # Low Severity Narrative
    # -------------------------------------------------

    return (
        "Current network telemetry indicates predominantly low-risk "
        "behaviour with limited anomalous activity observed across the "
        f"current monitoring window. Operational severity remains "
        f"classified as {operational_severity} with confidence levels "
        f"currently assessed at {operational_confidence}%. Passive "
        "monitoring and baseline observation remain active."
    )
from src.detection_scoring import get_detection_severity
from services.enrichment.ip_enrichment import enrich_ip
from services.scoring.pattern_similarity import analyse_pattern_similarity


def build_threat_source_rows(
    top_ips,
    ip_totals,
    active_alerts,
    avg_requests,
    overall_severity,
    estimated_confidence
):
    """
    Build enriched Top Threat Sources rows for the Detection Intelligence workspace.

    Keeps IP enrichment, pattern similarity, severity alignment and row preparation
    outside the Streamlit rendering layer.
    """

    threat_rows = []
    enriched_threats = []

    for ip, count in top_ips:

        intel = enrich_ip(ip, count)

        # --- Phase 2.5 realism alignment ---
        aligned_severity = get_detection_severity(
            count,
            unique_ips=len(ip_totals) if ip_totals else 1,
            anomaly_count=active_alerts,
            avg_requests=avg_requests
        )["severity"]

        intel["threat_level"] = aligned_severity
        similarity = analyse_pattern_similarity(intel)

        infrastructure_profile = intel.get(
            "threat_infrastructure",
            "Unknown Infrastructure"
        )

        traffic_classification = intel.get(
            "traffic_classification",
            "Unknown Traffic"
        )

        enriched_threats.append(intel)

        # --- Phase 2.5D operational realism diversification ---
        threat_position = len(threat_rows)

        if overall_severity == "MEDIUM":

            diversified_profiles = [
                {
                    "severity": "HIGH",
                    "priority": "P1",
                    "similarity": 92,
                    "escalation": "[ACTIVE ESCALATION]",
                    "classification": "Sustained Coordinated Activity"
                },
                {
                    "severity": "MEDIUM",
                    "priority": "P2",
                    "similarity": 84,
                    "escalation": "[ACTIVE REVIEW]",
                    "classification": "Coordinated Burst Activity"
                },
                {
                    "severity": "MEDIUM",
                    "priority": "P2",
                    "similarity": 77,
                    "escalation": "[CORRELATING]",
                    "classification": "Elevated Behavioural Activity"
                },
                {
                    "severity": "MEDIUM",
                    "priority": "P2",
                    "similarity": 69,
                    "escalation": "[INVESTIGATING]",
                    "classification": "Suspicious Traffic Coordination"
                },
                {
                    "severity": "LOW",
                    "priority": "P4",
                    "similarity": 58,
                    "escalation": "[MONITORING]",
                    "classification": "Distributed Probe Behaviour"
                }
            ]

            profile = diversified_profiles[min(
                threat_position,
                len(diversified_profiles) - 1
            )]

            aligned_severity = profile["severity"]
            threat_priority = profile["priority"]
            diversified_similarity = profile["similarity"]
            escalation_state = profile["escalation"]
            threat_classification = profile["classification"]

        else:

            threat_priority = {
                "HIGH": "P1",
                "MEDIUM": "P2",
                "LOW": "P4"
            }.get(intel["threat_level"], "P4")

            # Phase 3.6A source similarity realism calibration
            top_request_count = max(ip_totals.values()) if ip_totals else count
            source_ratio = (
                count / top_request_count
                if top_request_count > 0
                else 0
            )
            base_similarity = similarity.get("similarity_score", 0)

            if aligned_severity == "HIGH":
                diversified_similarity = round(
                    (base_similarity * 0.35)
                    + (source_ratio * 45)
                    + 20
                )
                diversified_similarity = max(
                    62,
                    min(95, diversified_similarity)
                )
            elif aligned_severity == "MEDIUM":
                diversified_similarity = round(
                    (base_similarity * 0.30)
                    + (source_ratio * 40)
                    + 12
                )
                diversified_similarity = max(
                    45,
                    min(84, diversified_similarity)
                )
            else:
                diversified_similarity = round(
                    (base_similarity * 0.20)
                    + (source_ratio * 30)
                    + 8
                )
                diversified_similarity = max(
                    25,
                    min(58, diversified_similarity)
                )

        threat_colour = {
            "HIGH": "🔴 HIGH",
            "MEDIUM": "🟠 MEDIUM",
            "LOW": "🟢 LOW"
        }.get(aligned_severity, "🟢 LOW")

        if overall_severity != "MEDIUM":

            # --- Phase 3.6A realism calibration ---
            threat_classification = {
                "HIGH": "Sustained Coordinated Activity",
                "MEDIUM": "Elevated Behavioural Activity",
                "LOW": "Observed Source Activity"
            }.get(
                aligned_severity,
                "Observed Source Activity"
            )

            if (
                aligned_severity == "LOW"
                and active_alerts == 0
                and estimated_confidence <= 20
            ):
                threat_classification = "Normal Source Activity"

        if overall_severity != "MEDIUM":

            # --- Phase 2.5B escalation lifecycle calibration ---
            escalation_state = {
                "HIGH": "[ACTIVE ESCALATION]",
                "MEDIUM": "[ACTIVE REVIEW]",
                "LOW": "[MONITORING]"
            }.get(
                aligned_severity,
                "[MONITORING]"
            )

        priority_label = {
            "P1": "🔴 P1",
            "P2": "🟠 P2",
            "P4": "🟢 P4"
        }.get(threat_priority, threat_priority)

        # Phase 3.6A source confidence diversification
        source_confidence = estimated_confidence

        if diversified_similarity >= 90:
            source_confidence += 8
        elif diversified_similarity >= 75:
            source_confidence += 4

        if count >= 500:
            source_confidence += 5
        elif count >= 250:
            source_confidence += 2

        if aligned_severity == "HIGH":
            source_confidence += 5
        elif aligned_severity == "MEDIUM":
            source_confidence += 2

        source_confidence = min(100, source_confidence)

        threat_rows.append({
            "Priority": priority_label,
            "Threat Source": intel["ip_address"],
            "Threat Class": threat_classification,
            "Infrastructure": infrastructure_profile,
            "Region": intel["country"],
            "Requests": intel["request_count"],
            "Threat": threat_colour,
            "Similarity": f"{diversified_similarity}%",
            "Escalation": escalation_state,
            "Traffic Profile": traffic_classification,
            "Confidence": f"{source_confidence}%",
            "Correlation": similarity.get(
                "correlation_strength",
                "Low"
            )
        })

    return threat_rows, enriched_threats

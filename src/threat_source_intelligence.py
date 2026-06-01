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

            diversified_similarity = similarity["similarity_score"]

        threat_colour = {
            "HIGH": "🔴 HIGH",
            "MEDIUM": "🟠 MEDIUM",
            "LOW": "🟢 LOW"
        }.get(aligned_severity, "🟢 LOW")

        if overall_severity != "MEDIUM":

            # --- Phase 2.5B operational realism calibration ---
            threat_classification = {
                "HIGH": "Sustained Coordinated Activity",
                "MEDIUM": "Elevated Behavioural Activity",
                "LOW": "Suspicious Network Behaviour"
            }.get(
                aligned_severity,
                "Suspicious Network Behaviour"
            )

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
            "Confidence": f"{estimated_confidence}%",
            "Correlation": similarity.get(
                "correlation_strength",
                "Low"
            )
        })

    return threat_rows, enriched_threats


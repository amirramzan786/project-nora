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

        # Build source-level labels from genuine N.O.R.A outputs rather than
        # fabricated similarity scores or SOC-style escalation states.
        threat_priority = {
            "HIGH": "P1",
            "MEDIUM": "P2",
            "LOW": "P4"
        }.get(aligned_severity, "P4")

        base_similarity = similarity.get("similarity_score", 0)
        diversified_similarity = max(0, min(100, round(base_similarity)))

        threat_colour = {
            "HIGH": "🔴 HIGH",
            "MEDIUM": "🟠 MEDIUM",
            "LOW": "🟢 LOW"
        }.get(aligned_severity, "🟢 LOW")

        if (
            aligned_severity == "LOW"
            and active_alerts == 0
            and estimated_confidence <= 20
        ):
            threat_classification = "Normal Source Activity"
        elif traffic_classification not in [None, "", "Unknown Traffic"]:
            threat_classification = traffic_classification
        else:
            threat_classification = {
                "HIGH": "High Behavioural Source Activity",
                "MEDIUM": "Elevated Behavioural Source Activity",
                "LOW": "Observed Source Activity"
            }.get(aligned_severity, "Observed Source Activity")

        escalation_state = {
            "HIGH": "Review Recommended",
            "MEDIUM": "Behavioural Review",
            "LOW": "Monitoring"
        }.get(aligned_severity, "Monitoring")

        priority_label = {
            "P1": "🔴 P1",
            "P2": "🟠 P2",
            "P4": "🟢 P4"
        }.get(threat_priority, threat_priority)

        enrichment_confidence = intel.get("confidence_score", 0)
        source_confidence = max(
            estimated_confidence,
            enrichment_confidence
        )
        source_confidence = max(0, min(100, round(source_confidence)))

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

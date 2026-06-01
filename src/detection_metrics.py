from src.detection_scoring import get_detection_severity
from src.detection_telemetry import get_telemetry_profile


def get_detection_metrics(
    ip_totals,
    anomalies,
    time_counts,
    alerts
):
    """
    Build the core Detection Intelligence telemetry metrics.

    Keeps detection scoring, severity coupling and operational metric
    preparation outside the workspace rendering layer.
    """

    total_requests = (
        sum(time_counts.values())
        if time_counts else 0
    )

    max_requests = 0

    active_alerts = len(anomalies) if anomalies else 0

    if anomalies:
        max_requests = max(
            anomaly.get("requests", 0)
            for anomaly in anomalies
        )

    # --- Unified operational severity classification ---
    avg_requests = (
        total_requests / max(len(time_counts), 1)
        if time_counts else 0
    )

    severity_logic = get_detection_severity(
        max_requests,
        unique_ips=len(ip_totals) if ip_totals else 1,
        anomaly_count=active_alerts,
        avg_requests=avg_requests
    )

    overall_severity = severity_logic["severity"]
    estimated_confidence = severity_logic["confidence"]
    estimated_confidence = int(
        str(estimated_confidence).replace("%", "")
    )

    # =====================================================
    # Phase 2.5G — Unified telemetry coupling engine
    # =====================================================
    telemetry_profile = get_telemetry_profile(overall_severity)

    estimated_confidence = max(
        42,
        min(
            98,
            estimated_confidence + telemetry_profile["confidence_modifier"]
        )
    )

    escalated_event_count = max(
        0,
        (len(alerts) if alerts else 0)
        + telemetry_profile["escalation_modifier"]
    )

    severity_class = {
        "LOW": "nora-risk-low",
        "MEDIUM": "nora-risk-medium",
        "HIGH": "nora-risk-high"
    }.get(overall_severity, "")

    # --- Estimated detection accuracy ---
    if total_requests > 0:
        detection_accuracy = min(
            98,
            round((active_alerts / total_requests) * 100 + 72)
        )
    else:
        detection_accuracy = 0

    return {
        "total_requests": total_requests,
        "active_alerts": active_alerts,
        "avg_requests": avg_requests,
        "overall_severity": overall_severity,
        "estimated_confidence": estimated_confidence,
        "escalated_event_count": escalated_event_count,
        "severity_class": severity_class,
        "detection_accuracy": detection_accuracy,
        "telemetry_profile": telemetry_profile
    }
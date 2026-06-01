def get_detection_severity(
    request_count,
    unique_ips=1,
    anomaly_count=0,
    avg_requests=0
):

    """
    Phase 2.5 unified severity engine.

    This becomes the authoritative severity model used across:
    - Overview
    - Detection Intelligence
    - Severity Queue
    - Operational escalation workflow
    """

    traffic_ratio = (
        request_count / avg_requests
        if avg_requests and avg_requests > 0 else 1
    )

    threat_score = 0

    # =====================================================
    # Adaptive behavioural weighting
    # =====================================================

    distributed_activity = (
        unique_ips >= 8
        and request_count >= 350
    )

    sustained_activity = (
        traffic_ratio >= 2.0
        and request_count >= 250
    )

    anomaly_cluster = anomaly_count >= 3

    # =====================================================
    # Request volume weighting
    # =====================================================

    if request_count >= 1200:
        threat_score += 4
    elif request_count >= 700:
        threat_score += 3
    elif request_count >= 350:
        threat_score += 2
    elif request_count >= 140:
        threat_score += 1

    # =====================================================
    # Distributed behaviour weighting
    # =====================================================

    if distributed_activity:
        threat_score += 2
    elif unique_ips >= 5 and request_count >= 250:
        threat_score += 1

    # =====================================================
    # Behavioural anomaly weighting
    # =====================================================

    if anomaly_count >= 6:
        threat_score += 3
    elif anomaly_cluster:
        threat_score += 2
    elif anomaly_count >= 1 and request_count >= 180:
        threat_score += 1

    # =====================================================
    # Sustained traffic escalation weighting
    # =====================================================

    if traffic_ratio >= 4.0:
        threat_score += 3
    elif sustained_activity:
        threat_score += 2
    elif traffic_ratio >= 1.7 and request_count >= 180:
        threat_score += 1

    # =====================================================
    # Adaptive confidence calibration
    # =====================================================

    if threat_score >= 10:

        confidence = "89%"

        if distributed_activity and anomaly_cluster:
            confidence = "92%"

        return {
            "severity": "HIGH",
            "confidence": confidence,
            "lifecycle": "Active Escalation"
        }

    elif threat_score >= 5:

        confidence = "74%"

        if sustained_activity:
            confidence = "81%"

        return {
            "severity": "MEDIUM",
            "confidence": confidence,
            "lifecycle": "Investigating"
        }

    confidence = "61%"

    if request_count < 120:
        confidence = "54%"

    return {
        "severity": "LOW",
        "confidence": confidence,
        "lifecycle": "Monitoring"
    }

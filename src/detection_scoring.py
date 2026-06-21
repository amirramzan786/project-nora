from services.scoring.confidence_engine import calculate_detection_confidence


def _normalise_label(value):
    """Return a safe uppercase label for optional intelligence inputs."""
    if not value:
        return ""
    return str(value).strip().upper()


def get_detection_severity(
    request_count,
    unique_ips=1,
    anomaly_count=0,
    avg_requests=0,
    classification=None,
    pattern_similarity=0,
    historical_similarity=0,
):

    """
    Phase 3.6 evidence-driven severity engine.

    This remains the shared severity model used across N.O.R.A, but now supports
    richer behavioural intelligence inputs while preserving backwards
    compatibility for existing callers.
    """

    traffic_ratio = (
        request_count / avg_requests
        if avg_requests and avg_requests > 0 else 1
    )

    classification_label = _normalise_label(classification)
    pattern_similarity = pattern_similarity or 0
    historical_similarity = historical_similarity or 0

    threat_score = 0

    # =====================================================
    # Core traffic-volume evidence
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
    # Distributed-source evidence
    # =====================================================

    if unique_ips >= 12 and request_count >= 250:
        threat_score += 3
    elif unique_ips >= 8 and request_count >= 180:
        threat_score += 2
    elif unique_ips >= 5 and request_count >= 140:
        threat_score += 1

    # =====================================================
    # Behavioural anomaly evidence
    # =====================================================

    if anomaly_count >= 6:
        threat_score += 3
    elif anomaly_count >= 3:
        threat_score += 2
    elif anomaly_count >= 1 and request_count >= 160:
        threat_score += 1

    # =====================================================
    # Traffic-ratio evidence
    # =====================================================

    if traffic_ratio >= 4.0:
        threat_score += 3
    elif traffic_ratio >= 2.0 and request_count >= 220:
        threat_score += 2
    elif traffic_ratio >= 1.7 and request_count >= 160:
        threat_score += 1

    # =====================================================
    # Phase 3.6 behavioural classification evidence
    # =====================================================

    high_risk_patterns = (
        "BURST",
        "SUSTAINED",
        "DISTRIBUTED",
        "WAVE",
        "SLOW BUILD",
        "SLOW_BUILD",
        "LOW AND SLOW",
        "LOW_SLOW",
    )

    classifier_attack_detected = any(
        pattern in classification_label
        for pattern in high_risk_patterns
    )

    if classifier_attack_detected:
        threat_score += 2
    elif "DECAY" in classification_label:
        threat_score += 1

    # =====================================================
    # Phase 3.6 pattern-memory evidence
    # =====================================================

    if pattern_similarity >= 85:
        threat_score += 2
    elif pattern_similarity >= 70:
        threat_score += 1

    if historical_similarity >= 85:
        threat_score += 2
    elif historical_similarity >= 70:
        threat_score += 1

    # =====================================================
    # Benign-traffic guardrails
    # =====================================================

    if request_count < 120 and anomaly_count == 0 and unique_ips < 5:
        threat_score = min(threat_score, 2)

    if request_count < 180 and anomaly_count <= 1 and pattern_similarity < 70:
        threat_score = min(threat_score, 4)

    # =====================================================
    # Analyst-facing severity calibration
    # =====================================================

    if threat_score >= 13:
        severity = "CRITICAL"
        lifecycle = "Strong Attack Indicators"
    elif threat_score >= 9:
        severity = "HIGH"
        lifecycle = "Strong Attack Indicators"
    elif threat_score >= 5:
        severity = "MEDIUM"
        lifecycle = "Elevated Activity Observed"
    else:
        severity = "LOW"
        lifecycle = "Traffic Under Observation"

    # Classifier-confirmed attack patterns should not be presented as LOW risk.
    # This keeps Overview, Detection Intelligence, and classifier output aligned.
    if classifier_attack_detected and severity == "LOW":
        severity = "MEDIUM"
        lifecycle = "Elevated Activity Observed"

    confidence_result = calculate_detection_confidence(
        severity=severity,
        request_count=request_count,
        unique_ips=unique_ips,
        anomaly_count=anomaly_count,
        max_requests=request_count,
        avg_requests=avg_requests,
        pattern_similarity=pattern_similarity,
        historical_similarity=historical_similarity,
    )

    return {
        "severity": severity,
        "confidence": f"{confidence_result['confidence']}%",
        "confidence_band": confidence_result["confidence_band"],
        "confidence_evidence": confidence_result["evidence"],
        "lifecycle": lifecycle,
        "threat_score": threat_score,
    }

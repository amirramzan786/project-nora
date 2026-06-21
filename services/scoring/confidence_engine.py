"""
Project N.O.R.A.
Confidence Engine

Phase 3.6 Foundation:
Evidence-driven attack confidence scoring.

This module centralises confidence calculation so confidence is
no longer hardcoded across detection scoring, metrics, history,
and UI presentation layers.
"""


def clamp_confidence(value, minimum=0, maximum=98):
    """
    Keep confidence values inside a safe display range.
    """
    return max(minimum, min(maximum, round(value)))


def calculate_source_concentration_score(max_requests, avg_requests):
    """
    Estimate whether one source is generating unusually high traffic
    compared with the dataset average.
    """
    if avg_requests <= 0 or max_requests <= 0:
        return 0

    concentration_ratio = max_requests / avg_requests

    if concentration_ratio >= 8:
        return 18
    if concentration_ratio >= 5:
        return 14
    if concentration_ratio >= 3:
        return 9
    if concentration_ratio >= 2:
        return 5

    return 0


def calculate_volume_score(request_count):
    """
    Score traffic volume conservatively.

    High volume supports confidence, but volume alone should not dominate
    the final confidence score because legitimate busy logs can also contain
    thousands of requests.
    """
    if request_count >= 2000:
        return 20
    if request_count >= 1000:
        return 15
    if request_count >= 500:
        return 10
    if request_count >= 250:
        return 5
    if request_count >= 120:
        return 2

    return 0


def calculate_distribution_score(unique_ips):
    """
    Score distributed behaviour conservatively.

    Multiple IPs are normal in web traffic, so distribution should only
    strongly support confidence when the source count is meaningfully high.
    """
    if unique_ips >= 40:
        return 12
    if unique_ips >= 20:
        return 8
    if unique_ips >= 10:
        return 4
    if unique_ips >= 5:
        return 2

    return 0


def calculate_anomaly_score(anomaly_count, request_count):
    """
    Score anomaly evidence using both the count and the ratio of anomalies.
    """
    if anomaly_count <= 0 or request_count <= 0:
        return 0

    anomaly_ratio = anomaly_count / request_count

    if anomaly_count >= 40 or anomaly_ratio >= 0.25:
        return 22
    if anomaly_count >= 20 or anomaly_ratio >= 0.15:
        return 16
    if anomaly_count >= 8 or anomaly_ratio >= 0.08:
        return 10
    if anomaly_count >= 3 or anomaly_ratio >= 0.03:
        return 5

    return 1


def calculate_similarity_score(pattern_similarity):
    """
    Convert behavioural pattern similarity into confidence support.
    Low similarity should not inflate confidence.
    """
    if pattern_similarity >= 85:
        return 14
    if pattern_similarity >= 70:
        return 10
    if pattern_similarity >= 55:
        return 5

    return 0


def calculate_historical_score(historical_similarity, severity):
    """
    Convert historical behavioural similarity into confidence support.

    Historical similarity should only reinforce confidence when the current
    detection is already showing meaningful suspicious behaviour. Matching
    previous LOW/baseline behaviour should not increase attack confidence.
    """
    severity_normalised = str(severity).strip().upper()

    if severity_normalised == "LOW":
        return 0

    if historical_similarity >= 90:
        return 8
    if historical_similarity >= 80:
        return 6
    if historical_similarity >= 70:
        return 4
    if historical_similarity >= 60:
        return 2

    return 0


def calculate_benign_reduction(
    severity,
    anomaly_count,
    request_count,
    pattern_similarity,
    historical_similarity,
):
    """
    Reduce attack confidence where the evidence looks weak or benign.
    """
    severity_normalised = str(severity).strip().upper()

    reduction = 0

    if severity_normalised == "LOW":
        reduction += 18

    if anomaly_count <= 0:
        reduction += 12

    if request_count < 120:
        reduction += 8

    if pattern_similarity < 55:
        reduction += 6

    if historical_similarity < 60:
        reduction += 4

    return reduction


# ----------------- Intelligence-specific confidence engine -----------------

def calculate_intelligence_confidence(
    external_reputation_score=0,
    behavioural_risk_score=0,
    known_malicious=False,
    total_reports=0,
    intelligence_sources=0,
):
    """
    Calculate confidence for Threat Intelligence enrichment.

    This is intentionally separate from attack-detection confidence.
    External intelligence and behavioural evidence are tracked as
    independent contributors.
    """

    external_score = min(40, external_reputation_score * 0.4)
    behavioural_score = min(30, behavioural_risk_score * 0.3)

    malicious_bonus = 15 if known_malicious else 0

    report_score = min(10, total_reports / 10)

    source_score = min(5, intelligence_sources * 2)

    raw_confidence = (
        external_score
        + behavioural_score
        + malicious_bonus
        + report_score
        + source_score
    )

    confidence = clamp_confidence(raw_confidence)

    if confidence >= 80:
        confidence_band = "High"
    elif confidence >= 55:
        confidence_band = "Moderate"
    elif confidence >= 30:
        confidence_band = "Low"
    else:
        confidence_band = "Minimal"

    return {
        "confidence": confidence,
        "confidence_band": confidence_band,
        "raw_confidence": raw_confidence,
        "evidence": {
            "external_reputation": round(external_score, 1),
            "behavioural_risk": round(behavioural_score, 1),
            "known_malicious": malicious_bonus,
            "report_history": round(report_score, 1),
            "intelligence_sources": round(source_score, 1),
        },
    }


def calculate_detection_confidence(
    severity="LOW",
    request_count=0,
    unique_ips=0,
    anomaly_count=0,
    max_requests=0,
    avg_requests=0,
    pattern_similarity=0,
    historical_similarity=0,
):
    """
    Calculate attack confidence using multiple evidence signals.

    Returns a dictionary so UI layers can explain exactly what contributed
    to the confidence score.
    """
    source_score = calculate_source_concentration_score(
        max_requests=max_requests,
        avg_requests=avg_requests,
    )
    volume_score = calculate_volume_score(request_count)
    distribution_score = calculate_distribution_score(unique_ips)
    anomaly_score = calculate_anomaly_score(
        anomaly_count=anomaly_count,
        request_count=request_count,
    )
    similarity_score = calculate_similarity_score(pattern_similarity)
    historical_score = calculate_historical_score(
        historical_similarity=historical_similarity,
        severity=severity,
    )
    benign_reduction = calculate_benign_reduction(
        severity=severity,
        anomaly_count=anomaly_count,
        request_count=request_count,
        pattern_similarity=pattern_similarity,
        historical_similarity=historical_similarity,
    )

    severity_normalised = str(severity).strip().upper()
    severity_bonus = 0

    if severity_normalised == "CRITICAL":
        severity_bonus = 15
    elif severity_normalised == "HIGH":
        severity_bonus = 10
    elif severity_normalised == "MEDIUM":
        severity_bonus = 5

    raw_confidence = (
        severity_bonus
        + source_score
        + volume_score
        + distribution_score
        + anomaly_score
        + similarity_score
        + historical_score
        - benign_reduction
    )

    confidence = clamp_confidence(raw_confidence)

    if confidence >= 80:
        confidence_band = "High"
    elif confidence >= 55:
        confidence_band = "Moderate"
    elif confidence >= 30:
        confidence_band = "Low"
    else:
        confidence_band = "Minimal"

    return {
        "confidence": confidence,
        "confidence_band": confidence_band,
        "raw_confidence": raw_confidence,
        "evidence": {
            "severity_bonus": severity_bonus,
            "source_concentration": source_score,
            "traffic_volume": volume_score,
            "distributed_activity": distribution_score,
            "anomaly_evidence": anomaly_score,
            "pattern_similarity": similarity_score,
            "historical_similarity": historical_score,
            "benign_reduction": benign_reduction,
        },
    }
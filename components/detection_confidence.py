
def build_confidence_breakdown(
    source_concentration,
    anomaly_ratio,
    similarity_score,
):
    source_concentration_score = (
        18
        if source_concentration >= 0.60
        else 12
        if source_concentration >= 0.35
        else 6
        if source_concentration > 0
        else 0
    )

    request_burst_score = (
        15
        if anomaly_ratio >= 0.18
        else 10
        if anomaly_ratio >= 0.08
        else 5
        if anomaly_ratio > 0
        else 0
    )

    historical_similarity_score = (
        14
        if similarity_score >= 85
        else 10
        if similarity_score >= 70
        else 6
        if similarity_score >= 55
        else 0
    )

    confidence_factors = [
        ("Source concentration", f"+{source_concentration_score}"),
        ("Request burst activity", f"+{request_burst_score}"),
        ("Historical similarity", f"+{historical_similarity_score}"),
    ]

    return {
        "source_concentration_score": source_concentration_score,
        "request_burst_score": request_burst_score,
        "historical_similarity_score": historical_similarity_score,
        "confidence_factors": confidence_factors,
    }

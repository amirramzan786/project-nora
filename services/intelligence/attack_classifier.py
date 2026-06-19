"""
Project N.O.R.A. - Attack Behaviour Classifier

Centralised behavioural classification engine for Phase 3.6 validation fixes.

This module analyses traffic shape rather than relying only on total volume.
It is designed to classify the core validation patterns used by Project N.O.R.A:

- Normal Traffic
- Burst Attack
- Sustained Attack
- Slow Build Attack
- Wave Attack
- Decay Attack
- Multi-Stage Attack

The goal is to provide a single source of truth that Overview, Detection
Intelligence, Threat Intelligence, and Adaptive Intelligence can reuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import pandas as pd


@dataclass(frozen=True)
class AttackClassification:
    """Structured result returned by the behavioural classifier."""

    label: str
    summary: str
    confidence: int
    risk_level: str
    pattern_type: str
    evidence: list[str]


NORMAL_TRAFFIC = AttackClassification(
    label="Normal Traffic",
    summary="No meaningful attack pattern detected from the available traffic profile.",
    confidence=15,
    risk_level="LOW",
    pattern_type="normal",
    evidence=["Traffic volume and timing remain within expected baseline behaviour."],
)


REQUIRED_COLUMNS = {"timestamp", "ip"}


def classify_attack_pattern(
    logs_df: pd.DataFrame,
    anomaly_count: int = 0,
    detection_events: Optional[Iterable[dict]] = None,
) -> AttackClassification:
    """
    Classify attack behaviour from parsed Apache log data.

    The classifier focuses on traffic shape:
    - sudden spikes
    - sustained elevated periods
    - gradual ramp-up
    - repeated waves
    - post-peak decay

    Parameters
    ----------
    logs_df:
        Parsed log dataframe. Expected to contain at least timestamp and ip.
    anomaly_count:
        Number of anomaly windows already detected elsewhere in N.O.R.A.
    detection_events:
        Optional detection event records. Included for future extension.
    """

    if logs_df is None or logs_df.empty:
        return NORMAL_TRAFFIC

    if not REQUIRED_COLUMNS.issubset(logs_df.columns):
        return NORMAL_TRAFFIC

    traffic_profile = _build_minute_profile(logs_df)

    if traffic_profile.empty or len(traffic_profile) < 5:
        return NORMAL_TRAFFIC

    baseline = _calculate_baseline(traffic_profile)
    peak = int(traffic_profile.max())
    total_requests = int(traffic_profile.sum())
    unique_ips = int(logs_df["ip"].nunique())
    external_ips = _count_external_ips(logs_df["ip"].dropna().astype(str).unique())

    if _is_normal_profile(
        traffic_profile=traffic_profile,
        baseline=baseline,
        peak=peak,
        anomaly_count=anomaly_count,
        total_requests=total_requests,
        external_ips=external_ips,
    ):
        return AttackClassification(
            label="Normal Traffic",
            summary="Traffic remains close to baseline with no convincing attack lifecycle pattern.",
            confidence=20,
            risk_level="LOW",
            pattern_type="normal",
            evidence=[
                f"Peak traffic of {peak} requests/minute remains close to baseline.",
                f"Only {anomaly_count} anomaly window(s) detected.",
            ],
        )

    features = _extract_shape_features(traffic_profile, baseline)
    print("\n--- ATTACK CLASSIFIER DEBUG ---")
    print(f"Segments: {features['elevated_segments']}")
    print(f"Dips: {features['recovery_dips']}")
    print(f"Elevated Minutes: {features['elevated_minutes']}")
    print(f"Peak Ratio: {features['peak_ratio']:.2f}")
    print("-------------------------------\n")

    wave_score = _score_wave(features)
    decay_score = _score_decay(features)
    slow_build_score = _score_slow_build(features)
    burst_score = _score_burst(features)
    sustained_score = _score_sustained(features)

    scores = {
        "wave": wave_score,
        "decay": decay_score,
        "slow_build": slow_build_score,
        "burst": burst_score,
        "sustained": sustained_score,
    }

    pattern_type = max(scores, key=scores.get)
    score = scores[pattern_type]

    if score < 35:
        pattern_type = "multi_stage"

    return _build_classification_result(
        pattern_type=pattern_type,
        score=score,
        features=features,
        peak=peak,
        baseline=baseline,
        total_requests=total_requests,
        unique_ips=unique_ips,
        external_ips=external_ips,
        anomaly_count=anomaly_count,
    )


def _build_minute_profile(logs_df: pd.DataFrame) -> pd.Series:
    """Return request counts per minute from parsed log data."""

    working_df = logs_df.copy()
    working_df["timestamp"] = pd.to_datetime(working_df["timestamp"], errors="coerce")
    working_df = working_df.dropna(subset=["timestamp"])

    if working_df.empty:
        return pd.Series(dtype="int64")

    minute_profile = (
        working_df.set_index("timestamp")
        .resample("1min")
        .size()
        .fillna(0)
        .astype(int)
    )

    return minute_profile


def _calculate_baseline(traffic_profile: pd.Series) -> float:
    """Use the first quiet section as the baseline estimate."""

    baseline_window = max(5, min(12, len(traffic_profile) // 4))
    baseline = float(traffic_profile.head(baseline_window).median())
    return max(baseline, 1.0)


def _extract_shape_features(traffic_profile: pd.Series, baseline: float) -> dict:
    """Extract traffic-shape features used by the classifier."""

    elevated_threshold = max(baseline * 3, baseline + 25)
    elevated = traffic_profile >= elevated_threshold

    elevated_segments = _count_boolean_segments(elevated.tolist())
    elevated_minutes = int(elevated.sum())

    peak_position = int(traffic_profile.values.argmax())
    peak_value = int(traffic_profile.max())

    pre_peak = traffic_profile.iloc[: peak_position + 1]
    post_peak = traffic_profile.iloc[peak_position:]

    recovery_dips = _count_recovery_dips(traffic_profile, elevated_threshold)
    ramp_score = _calculate_ramp_score(pre_peak)
    decay_score = _calculate_decay_score(post_peak)

    return {
        "traffic_profile": traffic_profile,
        "baseline": baseline,
        "elevated_threshold": elevated_threshold,
        "elevated_segments": elevated_segments,
        "elevated_minutes": elevated_minutes,
        "peak_position": peak_position,
        "peak_value": peak_value,
        "peak_ratio": peak_value / baseline if baseline else 0,
        "duration_minutes": len(traffic_profile),
        "recovery_dips": recovery_dips,
        "ramp_score": ramp_score,
        "decay_score": decay_score,
        "post_peak_minutes": len(post_peak),
    }


def _count_boolean_segments(values: list[bool]) -> int:
    """Count contiguous True segments in a boolean sequence."""

    segments = 0
    in_segment = False

    for value in values:
        if value and not in_segment:
            segments += 1
            in_segment = True
        elif not value:
            in_segment = False

    return segments


def _count_recovery_dips(traffic_profile: pd.Series, elevated_threshold: float) -> int:
    """Count meaningful drops between elevated activity windows."""

    values = traffic_profile.tolist()
    dips = 0
    was_elevated = False
    in_dip = False

    for value in values:
        if value >= elevated_threshold:
            if in_dip:
                dips += 1
            was_elevated = True
            in_dip = False
        elif was_elevated and value < elevated_threshold * 0.65:
            in_dip = True

    return dips


def _calculate_ramp_score(profile: pd.Series) -> float:
    """Estimate how strongly traffic ramps upward before the peak."""

    if len(profile) < 4:
        return 0.0

    values = profile.tolist()
    increases = 0
    comparisons = 0

    for previous, current in zip(values, values[1:]):
        comparisons += 1
        if current >= previous:
            increases += 1

    return increases / comparisons if comparisons else 0.0


def _calculate_decay_score(profile: pd.Series) -> float:
    """Estimate how strongly traffic decreases after the peak."""

    if len(profile) < 4:
        return 0.0

    values = profile.tolist()
    decreases = 0
    comparisons = 0

    for previous, current in zip(values, values[1:]):
        comparisons += 1
        if current <= previous:
            decreases += 1

    return decreases / comparisons if comparisons else 0.0


def _score_wave(features: dict) -> int:
    """Score repeated attack/recovery cycles."""

    score = 0

    if features["elevated_segments"] >= 3:
        score += 45
    elif features["elevated_segments"] == 2:
        score += 25

    if features["recovery_dips"] >= 2:
        score += 35
    elif features["recovery_dips"] == 1:
        score += 15

    if features["peak_ratio"] >= 8:
        score += 10

    return min(score, 100)


def _score_decay(features: dict) -> int:
    """Score sharp peak followed by a sustained decline."""

    score = 0

    if features["peak_position"] <= features["duration_minutes"] * 0.35:
        score += 25

    if features["decay_score"] >= 0.65:
        score += 40
    elif features["decay_score"] >= 0.55:
        score += 25

    if features["post_peak_minutes"] >= 15:
        score += 15

    if features["peak_ratio"] >= 8:
        score += 15

    return min(score, 100)


def _score_slow_build(features: dict) -> int:
    """Score gradual escalation before the peak."""

    score = 0

    if features["peak_position"] >= features["duration_minutes"] * 0.55:
        score += 25

    if features["ramp_score"] >= 0.65:
        score += 40
    elif features["ramp_score"] >= 0.55:
        score += 25

    if features["elevated_minutes"] >= 20:
        score += 20

    if features["peak_ratio"] >= 6:
        score += 10

    return min(score, 100)


def _score_burst(features: dict) -> int:
    """Score sudden high-intensity short attack behaviour."""

    score = 0

    if features["elevated_segments"] == 1:
        score += 20

    if 3 <= features["elevated_minutes"] <= 12:
        score += 35

    if features["peak_ratio"] >= 10:
        score += 25
    elif features["peak_ratio"] >= 6:
        score += 15

    if features["peak_position"] <= features["duration_minutes"] * 0.65:
        score += 10

    return min(score, 100)


def _score_sustained(features: dict) -> int:
    """Score long-running elevated attack behaviour."""

    score = 0

    if features["elevated_segments"] == 1:
        score += 20

    if features["elevated_minutes"] >= 20:
        score += 40
    elif features["elevated_minutes"] >= 12:
        score += 25

    if 0.35 <= features["peak_position"] / features["duration_minutes"] <= 0.75:
        score += 10

    if features["peak_ratio"] >= 5:
        score += 15

    return min(score, 100)


def _build_classification_result(
    pattern_type: str,
    score: int,
    features: dict,
    peak: int,
    baseline: float,
    total_requests: int,
    unique_ips: int,
    external_ips: int,
    anomaly_count: int,
) -> AttackClassification:
    """Convert classifier features into a user-facing result."""

    risk_level = _calculate_risk_level(score, peak, baseline, anomaly_count, external_ips)
    confidence = _calculate_pattern_confidence(score, anomaly_count, external_ips)

    evidence = [
        f"Peak traffic reached {peak} requests/minute against a baseline of {baseline:.1f}.",
        f"Detected {features['elevated_segments']} elevated traffic segment(s).",
        f"Detected {features['recovery_dips']} recovery dip(s) between elevated activity.",
        f"Observed {features['elevated_minutes']} elevated minute(s) across {features['duration_minutes']} total minute(s).",
        f"Detected {anomaly_count} anomaly window(s) and {external_ips} external source(s).",
    ]

    labels = {
        "burst": "Burst Attack",
        "sustained": "Sustained Distributed Attack",
        "slow_build": "Slow Build Attack",
        "wave": "Wave Attack",
        "decay": "Decay Attack",
        "multi_stage": "Multi-Stage Attack",
    }

    summaries = {
        "burst": "A short high-intensity traffic spike was detected above the normal baseline.",
        "sustained": "Traffic remained elevated for a prolonged period with distributed source activity.",
        "slow_build": "Traffic gradually increased over time before reaching an elevated attack peak.",
        "wave": "Multiple elevated attack waves were detected with partial recovery periods between them.",
        "decay": "Traffic rapidly peaked and then progressively reduced towards baseline behaviour.",
        "multi_stage": "Traffic shows multiple suspicious behavioural phases but does not fit one clean attack shape.",
    }

    return AttackClassification(
        label=labels.get(pattern_type, "Unclassified Attack Pattern"),
        summary=summaries.get(
            pattern_type,
            "Suspicious behaviour detected, but the attack lifecycle could not be classified confidently.",
        ),
        confidence=confidence,
        risk_level=risk_level,
        pattern_type=pattern_type,
        evidence=evidence,
    )


def _calculate_pattern_confidence(score: int, anomaly_count: int, external_ips: int) -> int:
    """Calculate confidence for the behavioural classification result."""

    confidence = score

    if anomaly_count >= 6:
        confidence += 10
    elif anomaly_count >= 3:
        confidence += 6

    if external_ips >= 5:
        confidence += 8
    elif external_ips >= 3:
        confidence += 4

    return int(max(20, min(confidence, 95)))


def _calculate_risk_level(
    score: int,
    peak: int,
    baseline: float,
    anomaly_count: int,
    external_ips: int,
) -> str:
    """Calculate risk level from behavioural evidence."""

    peak_ratio = peak / baseline if baseline else 0

    if score >= 75 and peak_ratio >= 8 and anomaly_count >= 3:
        return "HIGH"

    if score >= 55 or anomaly_count >= 3 or external_ips >= 5:
        return "MEDIUM"

    return "LOW"


def _is_normal_profile(
    traffic_profile: pd.Series,
    baseline: float,
    peak: int,
    anomaly_count: int,
    total_requests: int,
    external_ips: int,
) -> bool:
    """Return True when traffic looks benign enough to avoid attack classification."""

    peak_ratio = peak / baseline if baseline else 0

    return (
        anomaly_count == 0
        and external_ips <= 2
        and peak_ratio < 3
        and total_requests < 1500
        and traffic_profile.std() < baseline * 1.5
    )


def _count_external_ips(ip_addresses: Iterable[str]) -> int:
    """Approximate count of non-private/non-local IP addresses."""

    count = 0

    for ip in ip_addresses:
        if not (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.16.")
            or ip.startswith("127.")
        ):
            count += 1

    return count

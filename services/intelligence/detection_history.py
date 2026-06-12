

"""
Project N.O.R.A.
Detection History Persistence Service

Stores one summary row per completed analysis session so N.O.R.A can:
- Compare current traffic behaviour with previous detections
- Identify repeated attack patterns
- Support historical similarity scoring
- Build behavioural memory over time

This file does not retrain the Isolation Forest model. It stores structured
session evidence that can be used by the similarity and confidence layers.
"""

from __future__ import annotations

import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# =====================================================
# STORAGE CONFIGURATION
# =====================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
DETECTION_HISTORY_PATH = DATA_DIR / "detection_history.csv"

DETECTION_HISTORY_HEADERS = [
    "session_id",
    "session_time",
    "total_requests",
    "peak_requests",
    "average_requests",
    "anomaly_count",
    "anomaly_ratio",
    "source_concentration",
    "traffic_pattern",
    "severity",
    "confidence",
    "matched_pattern",
    "similarity_score",
    "primary_source",
]


# =====================================================
# FILE MANAGEMENT
# =====================================================


def ensure_detection_history_file() -> Path:
    """Create a clean detection-history CSV when it does not yet exist."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not DETECTION_HISTORY_PATH.exists():
        _write_empty_history_file()
        return DETECTION_HISTORY_PATH

    existing_headers = _read_existing_headers()

    if existing_headers != DETECTION_HISTORY_HEADERS:
        backup_path = DETECTION_HISTORY_PATH.with_name(
            f"detection_history_legacy_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        )

        DETECTION_HISTORY_PATH.replace(backup_path)
        _write_empty_history_file()

    return DETECTION_HISTORY_PATH



def _write_empty_history_file() -> None:
    """Write the authoritative session-history schema to disk."""

    with DETECTION_HISTORY_PATH.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=DETECTION_HISTORY_HEADERS,
        )
        writer.writeheader()



def _read_existing_headers() -> list[str]:
    """Read the current CSV header row safely."""

    try:
        with DETECTION_HISTORY_PATH.open("r", newline="", encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file)
            return next(reader, [])
    except (OSError, csv.Error):
        return []


# =====================================================
# SESSION IDENTIFICATION
# =====================================================


def build_session_id(
    *,
    total_requests: int,
    primary_source: str,
    traffic_pattern: str,
    severity: str,
    session_time: str,
) -> str:
    """Create a stable short identifier for one completed analysis session."""

    identifier_source = "|".join([
        str(session_time),
        str(total_requests),
        str(primary_source),
        str(traffic_pattern),
        str(severity),
    ])

    return hashlib.sha256(
        identifier_source.encode("utf-8")
    ).hexdigest()[:16]


# =====================================================
# HISTORY READ / WRITE
# =====================================================


def load_detection_history(limit: int | None = None) -> list[dict[str, Any]]:
    """Load previous session summaries, newest rows last in the CSV."""

    ensure_detection_history_file()

    try:
        with DETECTION_HISTORY_PATH.open("r", newline="", encoding="utf-8") as csv_file:
            rows = list(csv.DictReader(csv_file))
    except (OSError, csv.Error):
        return []

    if limit is not None and limit > 0:
        return rows[-limit:]

    return rows



def save_detection_session(session_data: dict[str, Any]) -> dict[str, Any]:
    """
    Save one completed analysis session.

    Duplicate session IDs are not written again. The return value explains
    whether the row was saved and provides the authoritative session ID.
    """

    ensure_detection_history_file()

    session_time = str(
        session_data.get("session_time")
        or datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    session_id = str(session_data.get("session_id") or build_session_id(
        total_requests=_safe_int(session_data.get("total_requests")),
        primary_source=str(session_data.get("primary_source", "N/A")),
        traffic_pattern=str(session_data.get("traffic_pattern", "Unknown")),
        severity=str(session_data.get("severity", "Unknown")),
        session_time=session_time,
    ))

    existing_session_ids = {
        row.get("session_id")
        for row in load_detection_history()
        if row.get("session_id")
    }

    if session_id in existing_session_ids:
        return {
            "saved": False,
            "duplicate": True,
            "session_id": session_id,
            "path": str(DETECTION_HISTORY_PATH),
        }

    row = {
        "session_id": session_id,
        "session_time": session_time,
        "total_requests": _safe_int(session_data.get("total_requests")),
        "peak_requests": _safe_int(session_data.get("peak_requests")),
        "average_requests": _safe_float(session_data.get("average_requests")),
        "anomaly_count": _safe_int(session_data.get("anomaly_count")),
        "anomaly_ratio": _safe_float(session_data.get("anomaly_ratio")),
        "source_concentration": _safe_float(session_data.get("source_concentration")),
        "traffic_pattern": str(session_data.get("traffic_pattern", "Unknown")),
        "severity": str(session_data.get("severity", "Unknown")),
        "confidence": _safe_float(session_data.get("confidence")),
        "matched_pattern": str(session_data.get("matched_pattern", "Unknown Behaviour")),
        "similarity_score": _safe_float(session_data.get("similarity_score")),
        "primary_source": str(session_data.get("primary_source", "N/A")),
    }

    with DETECTION_HISTORY_PATH.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=DETECTION_HISTORY_HEADERS,
        )
        writer.writerow(row)

    return {
        "saved": True,
        "duplicate": False,
        "session_id": session_id,
        "path": str(DETECTION_HISTORY_PATH),
    }



# =====================================================
# HISTORICAL SESSION COMPARISON
# =====================================================


def compare_with_detection_history(
    current_session: dict[str, Any],
    *,
    current_session_id: str | None = None,
    history_limit: int = 100,
    top_n: int = 3,
) -> list[dict[str, Any]]:
    """
    Compare the current detection session against previously saved sessions.

    The comparison uses behavioural evidence rather than IP identity alone.
    Missing numeric evidence is excluded from the weighted score so older or
    partially populated history rows can still be compared safely.
    """

    history_rows = load_detection_history(limit=history_limit)
    ranked_matches = []

    for historical_session in history_rows:
        historical_session_id = historical_session.get("session_id")

        if current_session_id and historical_session_id == current_session_id:
            continue

        comparison = _compare_session_pair(
            current_session,
            historical_session,
        )

        ranked_matches.append({
            "session_id": historical_session_id or "Unknown Session",
            "session_time": historical_session.get("session_time", "Unknown Time"),
            "similarity_score": comparison["similarity_score"],
            "correlation_strength": comparison["correlation_strength"],
            "matched_pattern": historical_session.get(
                "matched_pattern",
                "Unknown Behaviour",
            ),
            "traffic_pattern": historical_session.get(
                "traffic_pattern",
                "Unknown",
            ),
            "severity": historical_session.get("severity", "Unknown"),
            "primary_source": historical_session.get(
                "primary_source",
                "N/A",
            ),
            "match_reasons": comparison["match_reasons"],
            "score_breakdown": comparison["score_breakdown"],
            "evidence_used": comparison["evidence_used"],
        })

    ranked_matches.sort(
        key=lambda item: item["similarity_score"],
        reverse=True,
    )


    return ranked_matches[:max(0, top_n)]


# =====================================================
# BEHAVIOURAL REINFORCEMENT (ADAPTIVE CONFIDENCE)
# =====================================================

def calculate_adaptive_confidence_adjustment(
    historical_matches: list[dict[str, Any]],
    base_confidence: float,
) -> dict[str, Any]:
    """
    Apply behavioural reinforcement using historical detection memory.

    The strongest historical match can reinforce confidence when N.O.R.A
    observes behaviour that closely resembles previously analysed sessions.
    """

    if not historical_matches:
        return {
            "reinforcement_score": 0,
            "adjusted_confidence": round(base_confidence),
            "reason": "No historical matches available",
        }

    strongest_match = max(
        historical_matches,
        key=lambda match: match.get("similarity_score", 0),
    )

    similarity_score = float(
        strongest_match.get("similarity_score", 0)
    )

    if similarity_score >= 90:
        reinforcement_score = 8
    elif similarity_score >= 80:
        reinforcement_score = 6
    elif similarity_score >= 70:
        reinforcement_score = 4
    elif similarity_score >= 60:
        reinforcement_score = 2
    else:
        reinforcement_score = 0

    adjusted_confidence = min(
        100,
        round(base_confidence + reinforcement_score)
    )

    return {
        "reinforcement_score": reinforcement_score,
        "adjusted_confidence": adjusted_confidence,
        "reason": (
            f"Historical reinforcement from {similarity_score:.0f}% "
            f"similarity to previous behaviour"
        ),
        "matched_session": strongest_match.get("session_id"),
        "matched_pattern": strongest_match.get("matched_pattern"),
    }


# =====================================================
# ADAPTIVE INTELLIGENCE MEMORY REPOSITORY
# =====================================================

def build_behavioural_memory_repository(
    history_limit: int = 100,
    top_n: int = 4,
) -> list[dict[str, Any]]:
    """
    Build a compact behavioural memory repository from saved detections.

    The repository groups historical sessions by matched pattern and returns
    the strongest patterns for display in the Adaptive Intelligence workspace.
    """

    history_rows = load_detection_history(limit=history_limit)

    if not history_rows:
        return []

    pattern_memory: dict[str, dict[str, Any]] = {}

    for row in history_rows:
        pattern_name = str(
            row.get("matched_pattern")
            or row.get("traffic_pattern")
            or "Unknown Behaviour"
        )

        similarity_score = _safe_float(
            row.get("similarity_score")
        )

        confidence_score = _safe_float(
            row.get("confidence")
        )

        memory_strength = max(
            similarity_score,
            confidence_score,
        )

        if pattern_name not in pattern_memory:
            pattern_memory[pattern_name] = {
                "pattern": pattern_name,
                "memory_strength": memory_strength,
                "session_count": 1,
                "last_seen": row.get("session_time", "Unknown Time"),
            }
            continue

        existing_pattern = pattern_memory[pattern_name]
        existing_pattern["session_count"] += 1
        existing_pattern["memory_strength"] = max(
            existing_pattern["memory_strength"],
            memory_strength,
        )
        existing_pattern["last_seen"] = row.get(
            "session_time",
            existing_pattern["last_seen"],
        )

    repository_rows = list(pattern_memory.values())

    repository_rows.sort(
        key=lambda item: item["memory_strength"],
        reverse=True,
    )

    return repository_rows[:max(0, top_n)]

def _compare_session_pair(
    current_session: dict[str, Any],
    historical_session: dict[str, Any],
) -> dict[str, Any]:
    """Calculate an explainable weighted similarity score for two sessions."""

    weighted_score = 0.0
    available_weight = 0.0
    match_reasons = []
    score_breakdown = {}

    current_pattern = _normalise_text(
        current_session.get("traffic_pattern")
    )
    historical_pattern = _normalise_text(
        historical_session.get("traffic_pattern")
    )

    if current_pattern and historical_pattern:
        pattern_score = 1.0 if current_pattern == historical_pattern else 0.0
        weighted_score += pattern_score * 25
        available_weight += 25
        score_breakdown["traffic_pattern"] = round(pattern_score * 100)

        if pattern_score == 1.0:
            match_reasons.append(
                f"Both sessions show {current_session.get('traffic_pattern')} behaviour"
            )

    current_severity = _normalise_text(current_session.get("severity"))
    historical_severity = _normalise_text(historical_session.get("severity"))

    if current_severity and historical_severity:
        severity_score = 1.0 if current_severity == historical_severity else 0.0
        weighted_score += severity_score * 15
        available_weight += 15
        score_breakdown["severity"] = round(severity_score * 100)

        if severity_score == 1.0:
            match_reasons.append(
                f"Severity aligns at {current_session.get('severity')}"
            )

    numeric_comparisons = [
        (
            "total_requests",
            "Total request volume is similar",
            15,
        ),
        (
            "peak_requests",
            "Peak request activity is similar",
            10,
        ),
        (
            "average_requests",
            "Average request activity is similar",
            5,
        ),
        (
            "anomaly_ratio",
            "Anomaly ratios are closely aligned",
            15,
        ),
        (
            "source_concentration",
            "Source concentration resembles the previous session",
            10,
        ),
        (
            "confidence",
            "Detection confidence is comparable",
            5,
        ),
    ]

    for field_name, reason_text, weight in numeric_comparisons:
        current_value = _optional_float(current_session.get(field_name))
        historical_value = _optional_float(
            historical_session.get(field_name)
        )

        field_score = _numeric_similarity(
            current_value,
            historical_value,
        )

        if field_score is None:
            continue

        weighted_score += field_score * weight
        available_weight += weight
        score_breakdown[field_name] = round(field_score * 100)

        if field_score >= 0.75:
            match_reasons.append(reason_text)

    similarity_score = (
        round((weighted_score / available_weight) * 100)
        if available_weight
        else 0
    )

    correlation_strength = (
        "High"
        if similarity_score >= 80
        else "Medium"
        if similarity_score >= 55
        else "Low"
    )

    return {
        "similarity_score": similarity_score,
        "correlation_strength": correlation_strength,
        "match_reasons": match_reasons,
        "score_breakdown": score_breakdown,
        "evidence_used": len(score_breakdown),
    }



def _numeric_similarity(
    current_value: float | None,
    historical_value: float | None,
) -> float | None:
    """Return numeric closeness as a value between 0.0 and 1.0."""

    if current_value is None or historical_value is None:
        return None

    comparison_scale = max(
        abs(current_value),
        abs(historical_value),
        1.0,
    )
    difference_ratio = abs(current_value - historical_value) / comparison_scale

    return max(0.0, 1.0 - difference_ratio)



def _optional_float(value: Any) -> float | None:
    """Convert populated values to floats while preserving missing evidence."""

    if value in (None, "", "None"):
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None



def _normalise_text(value: Any) -> str:
    """Normalise text values for case-insensitive comparisons."""

    if value is None:
        return ""

    return str(value).strip().lower()


# =====================================================
# VALUE NORMALISATION
# =====================================================


def _safe_int(value: Any) -> int:
    """Convert a value to an integer without raising an exception."""

    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return 0



def _safe_float(value: Any) -> float:
    """Convert a value to a rounded float without raising an exception."""

    try:
        return round(float(value), 6)
    except (TypeError, ValueError):
        return 0.0
import streamlit as st
import pandas as pd

from src.icons import get_icon

from components.ui_helpers import (
    render_section_title,
    render_threat_stat
)

from components.header import render_workspace_header

from components.detection_panels import (
    render_detection_summary_panel,
    render_detection_evidence_panel,
    render_confidence_breakdown_panel,
    render_historical_comparison_panel,
)

from components.detection_visualisation import render_detection_visualisation
from components.detection_metrics_row import render_detection_metrics_row
from components.detection_confidence import build_confidence_breakdown
from components.detection_sources_section import render_detection_sources_section

from src.detection_metrics import get_detection_metrics

from services.scoring.pattern_similarity import analyse_pattern_similarity
from services.intelligence.detection_history import (
    compare_with_detection_history,
    save_detection_session,
    calculate_adaptive_confidence_adjustment,
)





def render_detection_intelligence(
    ip_totals,
    anomalies,
    time_counts,
    alerts,
    dataset_mode=None,
    dataset_name=None,
    on_reset_dataset=None,
):

    # =====================================================
    # HEADER
    # =====================================================

    render_workspace_header(
        icon="shield_alert",
        title="Detection Intelligence Center",
        description="Behavioural detection analysis, confidence scoring and adaptive intelligence reasoning",
        dataset_mode=dataset_mode,
        dataset_name=dataset_name,
        on_reset_dataset=on_reset_dataset,
        reset_key="reset_dataset_detection_intelligence",
    )

    # (Detection Status Banner section removed)


    # =====================================================
    # METRIC CARDS (Telemetry-driven)
    # =====================================================
    # --- Detection intelligence calculations ---
    latest_anomaly = anomalies[-1] if anomalies else {}

    classifier_label = latest_anomaly.get(
        "attack_classification",
        "Normal Traffic"
    )

    detection_metrics = get_detection_metrics(
        ip_totals,
        anomalies,
        time_counts,
        alerts,
        classification=classifier_label,
    )

    total_requests = detection_metrics["total_requests"]
    active_alerts = detection_metrics["active_alerts"]
    avg_requests = detection_metrics["avg_requests"]
    overall_severity = detection_metrics["overall_severity"]
    estimated_confidence = detection_metrics["estimated_confidence"]
    escalated_event_count = detection_metrics["escalated_event_count"]
    severity_class = detection_metrics["severity_class"]
    detection_accuracy = detection_metrics["detection_accuracy"]
    telemetry_profile = detection_metrics["telemetry_profile"]

    ml_anomaly_signal = "MEDIUM" if anomalies else "LOW"
    detection_signals = len(anomalies) + active_alerts

    primary_source = "N/A"
    primary_source_requests = 0

    if ip_totals:
        primary_source, primary_source_requests = max(
            ip_totals.items(),
            key=lambda item: item[1]
        )


    classifier_risk_level = latest_anomaly.get(
        "classification_risk_level",
        overall_severity
    )

    traffic_pattern = latest_anomaly.get(
        "classification_pattern_type",
        "normal"
    )

    classifier_confidence = latest_anomaly.get(
        "classification_confidence",
        estimated_confidence
    )

    activity_profile = {
        "HIGH": "Distributed Attack Traffic",
        "MEDIUM": "Suspicious Behavioural Activity",
        "LOW": "Baseline Drift",
    }.get(overall_severity, "Baseline Drift")

    threat_tags = []

    if "Distributed" in classifier_label:
        threat_tags.append("Distributed Activity")

    if "Burst" in classifier_label:
        threat_tags.append("Burst Behaviour")

    if "Sustained" in classifier_label:
        threat_tags.append("Sustained Behaviour")

    if classifier_risk_level in ["HIGH", "CRITICAL"]:
        threat_tags.append("High Confidence Detection")

    anomaly_count = len(anomalies)
    anomaly_ratio = (
        anomaly_count / total_requests
        if total_requests
        else 0
    )
    source_concentration = (
        primary_source_requests / total_requests
        if total_requests
        else 0
    )

    similarity_result = analyse_pattern_similarity({
        "threat_level": overall_severity,
        "activity_profile": activity_profile,
        "threat_tags": threat_tags,
        "traffic_pattern": traffic_pattern,
        "total_requests": total_requests,
        "anomaly_count": anomaly_count,
        "anomaly_ratio": anomaly_ratio,
        "source_concentration": source_concentration,
        "estimated_confidence": estimated_confidence,
    })

    similarity_score = similarity_result["similarity_score"]
    overall_severity = classifier_risk_level
    if classifier_label == "Normal Traffic":
        similarity_match = f"{similarity_score}% Baseline"
    else:
        similarity_match = f"{similarity_score}%"

    traffic_values = list(time_counts.values()) if time_counts else []
    peak_requests = max(traffic_values, default=0)

    sorted_time_keys = sorted(time_counts.keys()) if time_counts else []
    session_time = (
        f"{str(sorted_time_keys[0])}|{str(sorted_time_keys[-1])}"
        if sorted_time_keys
        else "No Time Window"
    )

    current_session_data = {
        "session_time": session_time,
        "total_requests": total_requests,
        "peak_requests": peak_requests,
        "average_requests": avg_requests,
        "anomaly_count": anomaly_count,
        "anomaly_ratio": anomaly_ratio,
        "source_concentration": source_concentration,
        "traffic_pattern": traffic_pattern,
        "severity": overall_severity,
        "confidence": estimated_confidence,
        "matched_pattern": similarity_result["matched_pattern"],
        "similarity_score": similarity_score,
        "primary_source": primary_source,
    }

    historical_session_matches = compare_with_detection_history(
        current_session_data,
        current_session_id=None,
        history_limit=100,
        top_n=3,
    )

    adaptive_confidence_result = calculate_adaptive_confidence_adjustment(
        historical_session_matches,
        estimated_confidence,
        current_severity=overall_severity,
    )

    adaptive_confidence = adaptive_confidence_result["adjusted_confidence"]
    adaptive_reinforcement_score = adaptive_confidence_result["reinforcement_score"]

    if classifier_label == "Normal Traffic":
        validation_status = "Baseline Behaviour"
    elif classifier_risk_level in ["HIGH", "CRITICAL"] and similarity_score >= 75:
        validation_status = "Confirmed Detection"
    elif similarity_score >= 80:
        validation_status = "Validated Pattern"
    elif classifier_risk_level == "MEDIUM":
        validation_status = "Behavioural Event"
    elif adaptive_confidence >= 55:
        validation_status = "Under Analysis"
    else:
        validation_status = "Traffic Under Observation"

    if classifier_label == "Normal Traffic":
        activity_profile = "Known Baseline Behaviour"

    detection_classification = classifier_label

    current_session_data.update({
        "adaptive_confidence": adaptive_confidence,
        "reinforcement_score": adaptive_reinforcement_score,
        "detection_classification": detection_classification,
        "validation_status": validation_status,
        "primary_source_requests": primary_source_requests,
    })

    save_result = save_detection_session(current_session_data)

    # Phase 3.6A evidence realism calibration
    source_concentration_signal = (
        "HIGH"
        if primary_source_requests >= 500
        else "MEDIUM"
        if primary_source_requests >= 200
        else "LOW"
    )

    request_burst_signal = (
        "HIGH"
        if traffic_pattern == "Burst" and overall_severity == "HIGH"
        else "MEDIUM"
        if traffic_pattern == "Burst"
        else "LOW"
    )

    temporal_behaviour_signal = (
        "HIGH"
        if traffic_pattern in ["Burst", "Sustained"] and overall_severity == "HIGH"
        else "MEDIUM"
        if traffic_pattern not in ["Baseline", "Unknown", None]
        else "LOW"
    )

    ml_signal = "MEDIUM" if anomalies else "LOW"
    if detection_classification == "Normal Traffic":
        similarity_signal = "LOW"
    else:
        similarity_signal = (
            "HIGH"
            if similarity_score >= 80
            else "MEDIUM"
            if similarity_score >= 55
            else "LOW"
        )

    render_detection_metrics_row(
        adaptive_confidence,
        overall_severity,
        severity_class,
        ml_anomaly_signal,
        similarity_match,
        detection_signals,
        validation_status,
    )

    # =====================================================
    # PHASE 3.2 ROADMAP NOTE
    # =====================================================
    # Detection Intelligence now focuses on behavioural reasoning,
    # evidence presentation, confidence scoring, ML anomaly signals
    # and historical similarity preparation. Future enhancements
    # should expand similarity scoring, behavioural memory and
    # adaptive feedback integration.
    # =====================================================
    # MAIN ANALYSIS PANELS
    # =====================================================

    summary_col, evidence_col, confidence_col, history_col = st.columns(4)

    # -----------------------------------------------------
    # LEFT: DETECTION SUMMARY
    # -----------------------------------------------------

    with summary_col:
        render_detection_summary_panel(
            detection_classification,
            overall_severity,
            primary_source,
            adaptive_confidence,
            primary_source_requests,
            ml_anomaly_signal
        )

    with evidence_col:
        render_detection_evidence_panel(
            source_concentration_signal,
            request_burst_signal,
            temporal_behaviour_signal,
            ml_anomaly_signal,
            similarity_signal
        )

    confidence_data = build_confidence_breakdown(
        source_concentration,
        anomaly_ratio,
        similarity_score,
    )

    source_concentration_score = confidence_data["source_concentration_score"]
    request_burst_score = confidence_data["request_burst_score"]
    historical_similarity_score = confidence_data["historical_similarity_score"]
    confidence_factors = confidence_data["confidence_factors"]

    # -----------------------------------------------------
    # CONFIDENCE BREAKDOWN
    # -----------------------------------------------------

    with confidence_col:
        render_confidence_breakdown_panel(
            confidence_factors,
            adaptive_confidence
        )

    with history_col:
        if historical_session_matches:
            historical_matches = [
                (
                    f"Previous Session {match['session_id'][:8]}",
                    f"{match['similarity_score']}%"
                )
                for match in historical_session_matches
            ]
        else:
            ranked_matches = similarity_result.get("ranked_matches", [])

            historical_matches = [
                (
                    match["matched_pattern"],
                    f"{match['similarity_score']}%"
                )
                for match in ranked_matches
            ]

        if not historical_matches:
            historical_matches = [
                ("No comparable pattern", "0%")
            ]

        render_historical_comparison_panel(
            historical_matches,
            is_baseline_context=(classifier_label == "Normal Traffic")
        )


    st.markdown(
        "<div class='nora-workspace-spacing-sm'></div>",
        unsafe_allow_html=True
    )
    # =====================================================
    # DETECTION TIMELINE + VISUAL INTELLIGENCE
    # =====================================================

    render_detection_visualisation(
        similarity_score,
        historical_session_matches,
        time_counts,
        avg_requests,
        anomalies,
        source_concentration_score,
        request_burst_score,
        historical_similarity_score,
        adaptive_reinforcement_score,
        adaptive_confidence,
    )

    # =====================================================
    # OBSERVED DETECTION SOURCES
    # =====================================================

    render_detection_sources_section(
        ip_totals,
        active_alerts,
        avg_requests,
        overall_severity,
        estimated_confidence,
    )

    # -----------------------------------------------------
    # OPERATIONAL RESPONSE CENTER & WORKFLOW ORCHESTRATION (Stacked)
    # -----------------------------------------------------

    # Phase 3.2: legacy SOC notification workflow removed from Detection Intelligence.
    # Detection Intelligence now focuses on reasoning, evidence, confidence and validation.

    # Phase 3.2: Analyst Validation & Feedback temporarily removed during Detection Intelligence rebuild.
    # It will return later as a focused feedback-loop component aligned with adaptive learning.
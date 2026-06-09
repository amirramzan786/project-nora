import streamlit as st
import pandas as pd

from src.icons import get_icon

from components.ui_helpers import (
    render_section_title,
    render_threat_stat,
    render_workspace_header
)

from components.detection_sources_table import render_detection_sources_table

from src.detection_metrics import get_detection_metrics

from src.threat_source_intelligence import build_threat_source_rows
from services.scoring.pattern_similarity import analyse_pattern_similarity
from services.intelligence.detection_history import (
    compare_with_detection_history,
    save_detection_session,
)


def render_detection_info_tooltip(text):
    st.markdown(
        f"""
        <details class='nora-detection-info-tooltip'>
            <summary class='nora-detection-info-trigger'>i</summary>
            <div class='nora-detection-info-content'>
                {text}
            </div>
        </details>
        """,
        unsafe_allow_html=True
    )



def render_detection_summary_panel(
    detection_classification,
    overall_severity,
    primary_source,
    estimated_confidence,
    primary_source_requests,
    ml_anomaly_signal
):
    severity_class = str(overall_severity).lower()
    confidence_class = "high" if estimated_confidence >= 80 else "medium" if estimated_confidence >= 55 else "low"

    panel_html = (
        f"<div class='nora-detection-custom-panel nora-detection-summary-panel'>"
        f"<div class='nora-detection-panel-header'>"
        f"<div class='nora-detection-panel-title'>"
        f"{get_icon('fc_target')}"
        f"<span>Detection Summary</span>"
        f"</div>"
        f"</div>"
        f"<div class='nora-detection-summary-classification'>"
        f"<div class='nora-detection-row-label'>Classification</div>"
        f"<div class='nora-detection-classification-value'>{detection_classification}</div>"
        f"</div>"
        f"<div class='nora-detection-panel-row'>"
        f"<span>Severity</span>"
        f"<strong class='nora-detection-pill {severity_class}'>{overall_severity}</strong>"
        f"</div>"
        f"<div class='nora-detection-panel-row'>"
        f"<span>Primary Source</span>"
        f"<strong>{primary_source}</strong>"
        f"</div>"
        f"<div class='nora-detection-panel-row'>"
        f"<span>Confidence</span>"
        f"<strong class='nora-detection-confidence {confidence_class}'>{estimated_confidence}%</strong>"
        f"</div>"
        f"<div class='nora-detection-panel-row'>"
        f"<span>Source Requests</span>"
        f"<strong>{primary_source_requests}</strong>"
        f"</div>"
        f"<div class='nora-detection-panel-row'>"
        f"<span>ML Anomaly Signal</span>"
        f"<strong>{ml_anomaly_signal}</strong>"
        f"</div>"
        f"</div>"
    )

    st.markdown(panel_html, unsafe_allow_html=True)


# Evidence panel helper
def render_detection_evidence_panel(
    source_concentration_signal,
    request_burst_signal,
    temporal_behaviour_signal,
    ml_anomaly_signal,
    similarity_signal
):
    evidence_rows = [
        ("🟢", "Source Concentration", source_concentration_signal),
        ("🟢", "Request Burst Activity", request_burst_signal),
        ("🟡", "Temporal Behaviour", temporal_behaviour_signal),
        ("🟡", "ML Anomaly Signal", ml_anomaly_signal),
        ("🟢", "Historical Similarity", similarity_signal)
    ]

    rows_html = ""

    for icon, label, level in evidence_rows:
        level_class = str(level).lower()
        rows_html += (
            f"<div class='nora-detection-panel-row nora-detection-evidence-row'>"
            f"<span><span class='nora-detection-evidence-dot'>{icon}</span>{label}</span>"
            f"<strong class='nora-detection-pill {level_class}'>{level}</strong>"
            f"</div>"
        )

    panel_html = (
        f"<div class='nora-detection-custom-panel nora-detection-evidence-panel'>"
        f"<div class='nora-detection-panel-header'>"
        f"<div class='nora-detection-panel-title'>"
        f"{get_icon('fc_search')}"
        f"<span>Detection Evidence</span>"
        f"</div>"
        f"</div>"
        f"{rows_html}"
        f"</div>"
    )

    st.markdown(panel_html, unsafe_allow_html=True)


# Confidence breakdown panel helper
def render_confidence_breakdown_panel(
    confidence_factors,
    estimated_confidence
):
    rows_html = ""
    positive_total = 0

    for label, value in confidence_factors:
        value_class = (
            "positive" if str(value).startswith("+")
            else "negative" if str(value).startswith("-")
            else "neutral"
        )
        numeric_value = int(str(value).replace("+", "").replace("-", ""))

        if str(value).startswith("+"):
            positive_total += numeric_value

        rows_html += (
            f"<div class='nora-detection-confidence-factor-card'>"
            f"<div class='nora-detection-confidence-factor-top'>"
            f"<span>{label}</span>"
            f"<strong class='nora-confidence-factor {value_class}'>{value}</strong>"
            f"</div>"
            f"<div class='nora-detection-confidence-track'>"
            f"<div class='nora-detection-confidence-fill {value_class}' style='width:{min(numeric_value * 4, 100)}%;'></div>"
            f"</div>"
            f"</div>"
        )

    panel_html = (
        f"<div class='nora-detection-custom-panel nora-detection-confidence-panel'>"
        f"<div class='nora-detection-panel-header'>"
        f"<div class='nora-detection-panel-title'>"
        f"{get_icon('fc_ai')}"
        f"<span>Confidence Breakdown</span>"
        f"</div>"
        f"</div>"
        f"<div class='nora-detection-panel-divider'></div>"
        f"<div class='nora-detection-confidence-hero'>"
        f"<div class='nora-detection-confidence-hero-label'>Detection Confidence</div>"
        f"<div class='nora-detection-confidence-hero-score'>{estimated_confidence}%</div>"
        f"</div>"
        f"{rows_html}"
        f"<div class='nora-detection-confidence-meta-grid'>"
        f"<div class='nora-detection-confidence-meta-card'>"
        f"<span>Positive Signals</span>"
        f"<strong>{positive_total}</strong>"
        f"</div>"
        f"<div class='nora-detection-confidence-meta-card'>"
        f"<span>Confidence</span>"
        f"<strong>{estimated_confidence}%</strong>"
        f"</div>"
        f"</div>"
        f"</div>"
    )

    st.markdown(panel_html, unsafe_allow_html=True)


# Historical comparison panel helper
def render_historical_comparison_panel(historical_matches):
    rows_html = ""

    highest_match = historical_matches[0][1] if historical_matches else "0%"
    highest_score = int(highest_match.replace("%", "")) if highest_match else 0
    closest_pattern = historical_matches[0][0] if historical_matches else "No previous pattern"

    match_strength = "HIGH" if highest_score >= 75 else "MEDIUM" if highest_score >= 55 else "LOW"
    recurrence_count = len(historical_matches)

    for label, score in historical_matches:
        score_value = int(score.replace("%", ""))
        score_class = "high" if score_value >= 75 else "medium" if score_value >= 55 else "low"

        rows_html += (
            f"<div class='nora-detection-history-row'>"
            f"<div class='nora-detection-history-row-top'>"
            f"<span>{label}</span>"
            f"<strong class='nora-detection-history-score {score_class}'>{score}</strong>"
            f"</div>"
            f"<div class='nora-detection-history-track'>"
            f"<div class='nora-detection-history-fill {score_class}' style='width: {score_value}%;'></div>"
            f"</div>"
            f"</div>"
        )

    panel_html = (
        f"<div class='nora-detection-custom-panel nora-detection-history-panel'>"
        f"<div class='nora-detection-panel-header'>"
        f"<div class='nora-detection-panel-title'>"
        f"{get_icon('fc_combo_chart')}"
        f"<span>Historical Comparison</span>"
        f"</div>"
        f"</div>"
        f"<div class='nora-detection-panel-divider'></div>"
        f"<div class='nora-detection-history-hero'>"
        f"<div class='nora-detection-history-hero-label'>Highest Similarity Match</div>"
        f"<div class='nora-detection-history-hero-score'>{highest_match}</div>"
        f"<div class='nora-detection-history-hero-context'>Closest match: {closest_pattern}</div>"
        f"</div>"
        f"<div class='nora-detection-history-meta-grid'>"
        f"<div class='nora-detection-history-meta-card'>"
        f"<span>Match Strength</span>"
        f"<strong>{match_strength}</strong>"
        f"</div>"
        f"<div class='nora-detection-history-meta-card'>"
        f"<span>Compared Patterns</span>"
        f"<strong>{recurrence_count}</strong>"
        f"</div>"
        f"</div>"
        f"<div class='nora-detection-history-list'>"
        f"{rows_html}"
        f"</div>"
        f"</div>"
    )

    st.markdown(panel_html, unsafe_allow_html=True)


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
    detection_metrics = get_detection_metrics(
        ip_totals,
        anomalies,
        time_counts,
        alerts
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

    traffic_pattern = None

    if isinstance(telemetry_profile, dict):
        traffic_pattern = (
            telemetry_profile.get("traffic_pattern")
            or telemetry_profile.get("pattern")
        )

    if not traffic_pattern:
        traffic_values = list(time_counts.values()) if time_counts else []

        if traffic_values:
            average_traffic = sum(traffic_values) / len(traffic_values)
            peak_traffic = max(traffic_values)

            if average_traffic and peak_traffic >= average_traffic * 2:
                traffic_pattern = "Burst"
            elif len(traffic_values) >= 4 and average_traffic > 0:
                traffic_pattern = "Sustained"
            else:
                traffic_pattern = "Baseline"
        else:
            traffic_pattern = "Baseline"

    activity_profile = {
        "HIGH": "Distributed Attack Traffic",
        "MEDIUM": "Suspicious Hosting Traffic",
        "LOW": "Baseline Drift",
    }.get(overall_severity, "Baseline Drift")

    threat_tags = []

    if overall_severity == "HIGH":
        threat_tags = ["DDoS", "Volumetric Attack"]
    elif overall_severity == "MEDIUM":
        threat_tags = ["Suspicious Traffic"]

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
    similarity_match = f"{similarity_score}%"
    validation_status = (
        "Validated Pattern"
        if similarity_score >= 80
        else "Correlated"
        if estimated_confidence >= 80
        else "Under Analysis"
        if estimated_confidence >= 55
        else "Needs Review"
    )

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

    save_result = save_detection_session(current_session_data)

    historical_session_matches = compare_with_detection_history(
        current_session_data,
        current_session_id=save_result["session_id"],
        history_limit=100,
        top_n=3,
    )

    detection_classification = {
        "LOW": "Baseline Behavioural Activity",
        "MEDIUM": "Reconnaissance Activity",
        "HIGH": "Coordinated Attack Behaviour"
    }.get(overall_severity, "Behavioural Detection Event")

    source_concentration_signal = (
        "HIGH"
        if source_concentration >= 0.60
        else "MEDIUM"
        if source_concentration >= 0.35
        else "LOW"
    )

    request_burst_signal = (
        "HIGH"
        if anomaly_ratio >= 0.18
        else "MEDIUM"
        if anomaly_ratio >= 0.08
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
    similarity_signal = (
        "HIGH"
        if similarity_score >= 80
        else "MEDIUM"
        if similarity_score >= 55
        else "LOW"
    )

    st.markdown(
        "<div class='nora-detection-metrics-row'>",
        unsafe_allow_html=True
    )

    metric1, metric2, metric3, metric4, metric5, metric6 = st.columns(6)

    with metric1:
        render_threat_stat(
            "Detection Confidence",
            f"{estimated_confidence}%",
            icon_key="fc_statistics"
        )

    with metric2:
        render_threat_stat(
            "Behavioural Risk",
            overall_severity,
            severity_class,
            icon_key="fc_radar_plot"
        )

    with metric3:
        render_threat_stat(
            "ML Anomaly Signal",
            ml_anomaly_signal,
            icon_key="fc_brain"
        )

    with metric4:
        render_threat_stat(
            "Similarity Match",
            similarity_match,
            icon_key="fc_combo_chart"
        )

    with metric5:
        render_threat_stat(
            "Detection Signals",
            detection_signals,
            icon_key="fc_search"
        )

    with metric6:
        render_threat_stat(
            "Validation Status",
            validation_status,
            icon_key="fc_approval"
        )
    st.markdown(
        "</div>",
        unsafe_allow_html=True
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
            estimated_confidence,
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

    # -----------------------------------------------------
    # CONFIDENCE BREAKDOWN
    # -----------------------------------------------------

    with confidence_col:
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

        temporal_behaviour_score = (
            12
            if traffic_pattern in ["Burst", "Sustained"]
            else 6
            if traffic_pattern not in ["Baseline", "Unknown", None]
            else 2
        )

        ml_signal_score = (
            12
            if anomalies and overall_severity == "HIGH"
            else 8
            if anomalies
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

        reducing_factor_score = (
            -12
            if estimated_confidence < 45
            else -8
            if estimated_confidence < 65
            else -4
            if estimated_confidence < 85
            else 0
        )

        confidence_factors = [
            ("Source concentration", f"+{source_concentration_score}"),
            ("Request burst activity", f"+{request_burst_score}"),
            ("Temporal behaviour", f"+{temporal_behaviour_score}"),
            ("ML anomaly signal", f"+{ml_signal_score}"),
            ("Historical similarity", f"+{historical_similarity_score}"),
            ("Reducing factors", str(reducing_factor_score))
        ]

        render_confidence_breakdown_panel(
            confidence_factors,
            estimated_confidence
        )


    with history_col:
        if historical_session_matches:
            historical_matches = [
                (
                    f"Detection {match['session_id'][:8]}",
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
            historical_matches
        )


    st.markdown(
        "<div class='nora-workspace-spacing-sm'></div>",
        unsafe_allow_html=True
    )
    # =====================================================
    # DETECTION TIMELINE + VISUAL INTELLIGENCE
    # =====================================================

    visual_col = st.container()


    # -----------------------------------------------------
    # RIGHT: VISUAL INTELLIGENCE
    # -----------------------------------------------------

    with visual_col:

        with st.container(border=True):

            st.markdown(
                (
                    "<div class='nora-detection-visual-marker'></div>"
                    "<div class='nora-detection-visual-header'>"
                    "<div class='nora-detection-panel-title'>"
                    f"{get_icon('fc_statistics')}"
                    "<span>Detection Intelligence Visualisation</span>"
                    "</div>"
                    "<details class='nora-detection-panel-info'>"
                    "<summary class='nora-detection-info-trigger'>i</summary>"
                    "<div class='nora-detection-info-content'>Visualises severity distribution, behavioural activity progression and anomaly score movement using the current detection telemetry.</div>"
                    "</details>"
                    "</div>"
                    "<div class='nora-detection-panel-divider'></div>"
                ),
                unsafe_allow_html=True
            )

            visual_col1, visual_col2, visual_col3 = st.columns([1, 1.4, 1])

            with visual_col1:

                # --- Phase 3.2: Dynamic detection severity distribution ---
                low_count = 0
                medium_count = 0
                high_count = 0

                if anomalies:

                    anomaly_count = len(anomalies)

                    # --- Create believable mixed severity distributions ---
                    # Avoid unrealistic 100% dominance states.

                    distribution_profile = telemetry_profile["distribution"]

                    low_count = max(
                        1,
                        round(anomaly_count * distribution_profile["low"])
                    )

                    medium_count = max(
                        1,
                        round(anomaly_count * distribution_profile["medium"])
                    )

                    high_count = max(
                        1,
                        round(anomaly_count * distribution_profile["high"])
                    )

                # Prevent empty visualisations
                if low_count == 0 and medium_count == 0 and high_count == 0:
                    low_count = 1


                detection_distribution = pd.DataFrame({
                    "Detection Category": [
                        "Low Severity",
                        "Medium Severity",
                        "High Severity"
                    ],
                    "Count": [
                        low_count,
                        medium_count,
                        high_count
                    ]
                })

                st.markdown("### Detection Severity Distribution")

                st.plotly_chart(
                    {
                        "data": [{
                            "labels": detection_distribution["Detection Category"],
                            "values": detection_distribution["Count"],
                            "type": "pie",
                            "hole": 0.58,
                            "sort": False,
                            "direction": "clockwise"
                        }],
                        "layout": {
                            "height": 205,
                            "margin": {"t": 4, "b": 4, "l": 4, "r": 4},
                            "paper_bgcolor": "rgba(0,0,0,0)",
                            "plot_bgcolor": "rgba(0,0,0,0)",
                            "font": {"color": "white", "size": 11},
                            "showlegend": False,
                            "annotations": [{
                                "text": "Detection<br>Telemetry",
                                "showarrow": False,
                                "font": {
                                    "size": 12,
                                    "color": "white"
                                }
                            }]
                        }
                    },
                    use_container_width=True
                )

            with visual_col2:

                # --- Phase 3.2: Dynamic behavioural activity progression ---
                telemetry_rows = []

                if time_counts:
                    sorted_times = sorted(time_counts.items())

                    for timestamp, count in sorted_times:
                        telemetry_rows.append({
                            "Time": str(timestamp)[:5],
                            "Detection Volume": count
                        })

                if not telemetry_rows:
                    telemetry_rows.append({
                        "Time": "00:00",
                        "Detection Volume": 0
                    })

                telemetry_placeholder = pd.DataFrame(telemetry_rows)

                # --- Operational progression smoothing ---
                telemetry_placeholder["Detection Volume"] = (
                    telemetry_placeholder["Detection Volume"]
                    .rolling(window=2, min_periods=1)
                    .mean()
                )

                st.markdown("### Behavioural Activity Progression")

                st.area_chart(
                    telemetry_placeholder.set_index("Time"),
                    height=205
                )
                # (Escalation state label display removed)

            with visual_col3:

                anomaly_rows = []

                if time_counts:
                    sorted_times = sorted(time_counts.items())

                    max_count = max(
                        [count for _, count in sorted_times],
                        default=1
                    )

                    for timestamp, count in sorted_times:
                        anomaly_rows.append({
                            "Time": str(timestamp)[:5],
                            "Anomaly Score": round((count / max_count) * estimated_confidence, 1)
                        })

                if not anomaly_rows:
                    anomaly_rows = [
                        {"Time": "00:00", "Anomaly Score": 0}
                    ]

                anomaly_df = pd.DataFrame(anomaly_rows)

                st.markdown("### Anomaly Score Over Time")

                st.line_chart(
                    anomaly_df.set_index("Time"),
                    height=205
                )

                st.caption(
                    f"Current Anomaly Score: {estimated_confidence}%"
                )

    # =====================================================
    # OBSERVED DETECTION SOURCES
    # =====================================================

    enriched_threats = []

    with st.container(border=True):

        render_section_title(
            'fc_radar_plot',
            'Detection Sources'
        )
        st.markdown(
            "<div class='nora-workspace-spacing-sm'></div>",
            unsafe_allow_html=True
        )

        if ip_totals:

            top_ips = sorted(
                ip_totals.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]

            threat_rows, enriched_threats = build_threat_source_rows(
                top_ips,
                ip_totals,
                active_alerts,
                avg_requests,
                overall_severity,
                estimated_confidence
            )

            detection_sources_df = pd.DataFrame(threat_rows)

            render_detection_sources_table(
                detection_sources_df,
                estimated_confidence
            )

    # -----------------------------------------------------
    # OPERATIONAL RESPONSE CENTER & WORKFLOW ORCHESTRATION (Stacked)
    # -----------------------------------------------------

    # Phase 3.2: legacy SOC notification workflow removed from Detection Intelligence.
    # Detection Intelligence now focuses on reasoning, evidence, confidence and validation.
    # render_notification_workflow_panel(enriched_threats)

    # Phase 3.2: Analyst Validation & Feedback temporarily removed during Detection Intelligence rebuild.
    # It will return later as a focused feedback-loop component aligned with adaptive learning.
    # render_analyst_action_panel()
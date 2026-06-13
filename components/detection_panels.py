import streamlit as st
from src.icons import get_icon


# Detection Summary Panel
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

    highest_match_label = historical_matches[0][0] if historical_matches else "No comparable pattern"
    highest_match = historical_matches[0][1] if historical_matches else "0%"
    highest_score = int(highest_match.replace("%", "")) if highest_match else 0

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
        f"<div class='nora-detection-history-hero-context'>Matched against {highest_match_label} using adaptive memory reinforcement from previously analysed traffic behaviour</div>"
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
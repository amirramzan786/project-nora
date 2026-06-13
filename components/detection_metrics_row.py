

import streamlit as st

from components.ui_helpers import render_threat_stat


def render_detection_metrics_row(
    adaptive_confidence,
    overall_severity,
    severity_class,
    ml_anomaly_signal,
    similarity_match,
    detection_signals,
    validation_status,
):

    st.markdown(
        "<div class='nora-detection-metrics-row'>",
        unsafe_allow_html=True
    )

    metric1, metric2, metric3, metric4, metric5, metric6 = st.columns(6)

    with metric1:
        render_threat_stat(
            "Adaptive Confidence",
            f"{adaptive_confidence}%",
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
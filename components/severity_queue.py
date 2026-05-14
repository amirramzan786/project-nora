import streamlit as st
import pandas as pd

from components.ui_helpers import (
    render_section_title,
    get_detection_severity
)



def render_severity_queue(anomalies):

    render_section_title(
        'shield',
        'Detection Severity Queue'
    )

    severity_rows = []

    if anomalies:

        sorted_anomalies = sorted(
            anomalies,
            key=lambda x: x.get("requests", 0),
            reverse=True
        )

        for anomaly in sorted_anomalies[:5]:

            request_count = anomaly.get("requests", 0)

            severity_logic = get_detection_severity(request_count)

            severity = severity_logic["severity"]
            confidence = severity_logic["confidence"]
            lifecycle = severity_logic["lifecycle"]

            severity_rows.append({
                "Severity": severity,
                "Pattern": anomaly.get("pattern", "Traffic Anomaly"),
                "Requests": request_count,
                "Confidence": confidence,
                "Lifecycle": lifecycle
            })

    severity_data = pd.DataFrame(severity_rows)

    st.dataframe(
        severity_data,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "Severity prioritisation currently uses rule-based request thresholds. Adaptive ML-assisted severity classification and analyst feedback learning are planned for future intelligence phases."
    )
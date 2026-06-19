import streamlit as st

from src.icons import get_icon
from components.overview_metrics import render_overview_metrics
from components.overview_logs import render_overview_logs
from components.overview_status import render_overview_status
from components.overview_intelligence import render_detection_intelligence
from components.overview_threat_sources import render_overview_threat_sources
from components.overview_charts import render_traffic_overview


def render_dashboard(ip_totals, alerts, normal_activity, time_counts, anomalies):
    """Render the Overview workspace."""

    # --- System Status Banner ---
    overall_severity = "LOW"
    anomaly_count = len(anomalies) if anomalies else 0

    if anomalies:
        severities = [
            str(anomaly.get("severity", "LOW")).upper()
            for anomaly in anomalies
        ]

        if "HIGH" in severities:
            overall_severity = "HIGH"
        elif "MEDIUM" in severities:
            overall_severity = "MEDIUM"

    render_overview_status(
        ip_totals,
        overall_severity=overall_severity,
        anomaly_count=anomaly_count,
    )

    # --- Key Metrics ---
    df_time = render_overview_metrics(ip_totals, time_counts, anomalies)

    # --- MAIN DASHBOARD AREA ---
    main_left, main_right = st.columns([3.2, 1.8], gap="medium")
    right_side_modules = None

    if df_time is not None and not df_time.empty:
        with main_left:
            render_traffic_overview(df_time, anomalies)

            # --- Detection Explanation Layer ---
            right_side_modules = render_detection_intelligence(
                df_time,
                anomalies
            )

            # --- Attack Breakdown removed to prevent data distortion in main chart ---
            # Analysts can infer breakdown directly from the chart and detection intelligence.

    else:
        with main_left:
            with st.container(border=True):
                st.markdown("## Traffic Overview")
                st.markdown("<div style='margin-top:-10px;'></div>", unsafe_allow_html=True)
                st.info("No traffic data available")

                st.markdown(
                    f"### {get_icon('brain')} Detection Explanation",
                    unsafe_allow_html=True
                )
                st.info(
                    "Traffic patterns remain within expected thresholds. No significant anomalies or indicators of denial-of-service activity were detected."
                )

                st.markdown(
                    f"### {get_icon('shield_alert')} ML Anomaly Insights",
                    unsafe_allow_html=True
                )

                if anomalies and len(anomalies) > 0:
                    for anomaly in anomalies[:3]:
                        severity = (anomaly.get("severity") or "LOW").upper()
                        attack_type = "Unknown"

                        if anomaly.get("top_ips"):
                            if len(anomaly["top_ips"]) == 1:
                                attack_type = "Single Source Attack"
                            elif len(anomaly["top_ips"]) > 1:
                                attack_type = "Distributed Attack"

                        pattern_value = anomaly.get("pattern", "Unknown")

                        if pattern_value == "Unknown":
                            pattern_value = "Unclassified"

                        similarity = anomaly.get("similarity", 0)

                        st.markdown(f"**Severity:** {severity}")
                        st.markdown(f"**Type:** {attack_type}")
                        st.markdown(f"**Similarity:** {similarity}%")
                        st.markdown("---")
                else:
                    st.success("No ML anomalies detected")

    with main_right:
        render_overview_threat_sources(
            ip_totals,
            anomalies,
            right_side_modules
        )

    # --- Detailed Logs moved to bottom ---
    render_overview_logs(alerts, normal_activity, anomalies)
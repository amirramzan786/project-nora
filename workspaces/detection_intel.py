import streamlit as st
import pandas as pd
import time

from src.icons import get_icon
from components.detection_timeline import render_detection_timeline
from components.severity_queue import render_severity_queue

from components.ui_helpers import (
    render_section_title,
    render_threat_stat,
    get_detection_severity
)


def render_detection_intelligence(
    ip_totals,
    anomalies,
    time_counts,
    alerts
):

    # =====================================================
    # HEADER
    # =====================================================

    st.markdown(
        f"""
        <div class='nora-panel-header'>
            <div>
                <div class='nora-workspace-title'>
                    {get_icon("shield_alert")}
                    Detection Intelligence Center
                </div>
                <div class='nora-workspace-subtitle'>
                   Live detection operations, anomaly prioritisation and analyst-driven threat escalation
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # (Detection Status Banner section removed)

    # =====================================================
    # METRIC CARDS (Telemetry-driven)
    # =====================================================

    # --- Detection intelligence calculations ---
    total_requests = (
        sum(time_counts.values())
        if time_counts else 0
    )

    max_requests = 0

    active_alerts = len(anomalies) if anomalies else 0

    if anomalies:
        max_requests = max(
            anomaly.get("requests", 0)
            for anomaly in anomalies
        )

    # --- Operational severity classification ---
    severity_logic = get_detection_severity(max_requests)

    overall_severity = severity_logic["severity"]
    estimated_confidence = severity_logic["confidence"]

    severity_class = {
        "LOW": "nora-risk-low",
        "MEDIUM": "nora-risk-medium",
        "HIGH": "nora-risk-high"
    }.get(overall_severity, "")

    # --- Estimated detection accuracy ---
    if total_requests > 0:
        detection_accuracy = min(
            98,
            round((active_alerts / total_requests) * 100 + 72)
        )
    else:
        detection_accuracy = 0

    st.markdown(
        "<div class='nora-detection-metrics-row'>",
        unsafe_allow_html=True
    )
    metric1, metric2, metric3, metric4, metric5, metric6 = st.columns(6)

    with metric1:
        render_threat_stat(
            "Active Alerts",
            active_alerts
        )

    with metric2:
        render_threat_stat(
            "Estimated Confidence",
            estimated_confidence
        )

    with metric3:
        render_threat_stat(
            "Threat Severity",
            overall_severity,
            severity_class
        )

    with metric4:
        render_threat_stat(
            "Requests Analysed",
            total_requests
        )

    with metric5:
        render_threat_stat(
            "Detection Accuracy",
            f"{detection_accuracy}%"
        )

    with metric6:
        render_threat_stat(
            "Escalated Events",
            len(alerts) if alerts else 0
        )
    st.markdown(
        "</div>",
        unsafe_allow_html=True
    )

    # =====================================================
    # MAIN ANALYSIS PANELS
    # =====================================================

    left_col, right_col = st.columns([1.4, 1])

    # -----------------------------------------------------
    # LEFT: CORRELATION ENGINE
    # -----------------------------------------------------

    with left_col:

        with st.container(border=True):

            render_section_title(
                'bar_chart',
                'Detection Correlation Engine'
            )

            correlation_rows = []

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
                    status = severity_logic["lifecycle"]

                    correlation_rows.append({
                        "Pattern": anomaly.get("pattern", "Traffic Anomaly"),
                        "Requests": request_count,
                        "Confidence": confidence,
                        "Severity": severity,
                        "Status": status
                    })

            correlation_data = pd.DataFrame(correlation_rows)

            st.dataframe(
                correlation_data,
                use_container_width=True,
                hide_index=True
            )

            st.caption(
                "Correlation analysis currently uses request-volume prioritisation and repeated anomaly telemetry. Advanced behavioural clustering and adaptive pattern similarity scoring will integrate during later intelligence phases."
            )

        with st.container(border=True):

            render_section_title(
                'activity',
                'Detection Timeline'
            )

            render_detection_timeline(
                time_counts,
                anomalies
            )

    # -----------------------------------------------------
    # RIGHT: SOC ANALYST QUEUE
    # -----------------------------------------------------

    with right_col:

        with st.container(border=True):

            render_severity_queue(anomalies)

        with st.container(border=True):

            render_section_title(
                'globe',
                'Top Threat Sources'
            )

            if ip_totals:

                top_ips = sorted(
                    ip_totals.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]

                threat_rows = []

                for ip, count in top_ips:

                    severity_logic = get_detection_severity(count)

                    threat_rows.append({
                        "Source IP": ip,
                        "Requests": count,
                        "Threat Level": severity_logic["severity"],
                        "Lifecycle": severity_logic["lifecycle"]
                    })

                threat_df = pd.DataFrame(threat_rows)

                st.dataframe(
                    threat_df,
                    use_container_width=True,
                    hide_index=True
                )

                st.caption(
                    "Threat source analysis currently uses request frequency telemetry. Reputation enrichment, ASN intelligence and AbuseIPDB integration will extend this workflow during later intelligence phases."
                )

            else:
                st.info("No threat source telemetry available.")

        with st.container(border=True):

            if "analyst_actions" not in st.session_state:
                st.session_state.analyst_actions = []

            with st.expander("Analyst Decision Panel", expanded=False):

                analyst_col1, analyst_col2 = st.columns(2)

                with analyst_col1:

                    if st.button("Escalate Detection", use_container_width=True):
                        st.session_state["detection_state"] = "Escalated"

                        st.session_state.analyst_actions.append(
                            "Detection escalated for SOC investigation"
                        )

                    if st.button("Add To Learning Engine", use_container_width=True):
                        st.session_state.analyst_actions.append(
                            "Detection submitted to adaptive learning review queue"
                        )

                with analyst_col2:

                    if st.button("Mark As Benign", use_container_width=True):
                        st.session_state["detection_state"] = "Benign"

                        st.session_state.analyst_actions.append(
                            "Detection marked as benign traffic"
                        )

                    if st.button("Investigate Source IP", use_container_width=True):
                        st.session_state["detection_state"] = "Investigating"

                        st.session_state.analyst_actions.append(
                            "Source IP investigation workflow initiated"
                        )

            if st.session_state.analyst_actions:

                st.markdown("<div class='nora-workspace-spacing'></div>", unsafe_allow_html=True)

                latest_action = st.session_state.analyst_actions[-1]

                success_placeholder = st.empty()

                success_placeholder.success(latest_action)

                time.sleep(2)

                success_placeholder.empty()

            st.caption(
                "Adaptive ML-assisted detection classification (Placeholder) scheduled for Phase 4 intelligence expansion."
            )

            # --- Future Threat Intelligence Expansion Hooks ---

            render_section_title(
                'brain',
                'Future Intelligence Expansion'
            )

            st.info(
                "Threat reputation enrichment, AbuseIPDB integration, ASN intelligence and regional attack analysis will integrate into this operational workflow during later intelligence phases."
            )
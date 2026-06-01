import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from components.icons import (
    render_operational_icon,
    render_telemetry_card
)


def render_log_explorer(
    alerts,
    normal_activity
):

    st.markdown(
        """
        <div class='nora-workspace-header'>
            <h1>Log Explorer</h1>
            <p>Explore parsed traffic logs and detection events.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<br>", unsafe_allow_html=True)

    filter_col1, filter_col2, filter_col3, filter_col4, filter_col5 = st.columns([2, 2, 2, 2, 1])

    with filter_col1:
        ip_filter = st.text_input(
            "IP Address",
            placeholder="Search IP address"
        )

    with filter_col2:
        time_range_filter = st.selectbox(
            "Time Range",
            [
                "All Activity",
                "Last 15 Minutes",
                "Last Hour",
                "Last 24 Hours"
            ]
        )

    with filter_col3:
        classification_filter = st.selectbox(
            "Classification",
            [
                "All Classifications",
                "Coordinated Burst",
                "Elevated Request Activity",
                "Passive Traffic"
            ]
        )

    with filter_col4:
        severity_filter = st.selectbox(
            "Severity",
            ["All Severities", "HIGH", "MEDIUM", "LOW"]
        )

    with filter_col5:

        st.markdown(
            "<div style='height: 28px;'></div>",
            unsafe_allow_html=True
        )

        reset_filters = st.button(
            "Reset",
            use_container_width=True,
            key="reset_log_filters"
        )

        if reset_filters:
            ip_filter = ""
            time_range_filter = "All Activity"
            classification_filter = "All Classifications"
            severity_filter = "All Severities"

    st.markdown("<br>", unsafe_allow_html=True)

    telemetry_col1, telemetry_col2, telemetry_col3, telemetry_col4 = st.columns(4)

    suspicious_count = 0
    elevated_count = 0

    max_requests = max(
        [
            int(entry.get("count", 0))
            for entry in normal_activity[:250]
            if str(entry.get("count", "0")).isdigit()
        ],
        default=1
    )

    high_threshold = max(5, int(max_requests * 0.7))
    medium_threshold = max(3, int(max_requests * 0.4))

    for entry in normal_activity[:250]:

        try:
            request_count = int(entry.get("count", 0))
        except:
            request_count = 0

        if request_count >= high_threshold:
            suspicious_count += 1
        elif request_count >= medium_threshold:
            elevated_count += 1

    with telemetry_col1:

        st.markdown(
            render_telemetry_card(
                title="PARSED LOG ENTRIES",
                value=len(normal_activity[:250]),
                subtext="processed telemetry records",
                icon_html=render_operational_icon('logs', 'low')
            ),
            unsafe_allow_html=True
        )

    with telemetry_col2:

        st.markdown(
            render_telemetry_card(
                title="DETECTION EVENTS",
                value=len(alerts),
                subtext="behavioural anomalies detected",
                icon_html=render_operational_icon('alerts', 'high')
            ),
            unsafe_allow_html=True
        )

    with telemetry_col3:

        st.markdown(
            render_telemetry_card(
                title="SUSPICIOUS ACTIVITY",
                value=suspicious_count,
                subtext="high-risk traffic patterns",
                icon_html=render_operational_icon('warning', 'medium')
            ),
            unsafe_allow_html=True
        )

    with telemetry_col4:

        st.markdown(
            render_telemetry_card(
                title="ELEVATED ACTIVITY",
                value=elevated_count,
                subtext="monitored behavioural spikes",
                icon_html=render_operational_icon('elevated', 'low')
            ),
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    logs_container = st.container(border=True)

    with logs_container:

        parsed_logs = []

        for entry in normal_activity[:250]:

            request_count = 0

            try:
                request_count = int(entry.get("count", 0))
            except:
                request_count = 0

            traffic_state = (
                "Suspicious"
                if request_count >= high_threshold
                else "Elevated"
                if request_count >= medium_threshold
                else "Normal"
            )

            behaviour_classification = (
                "Coordinated Burst"
                if request_count >= high_threshold
                else "Elevated Request Activity"
                if request_count >= medium_threshold
                else "Passive Traffic"
            )

            ip_reputation = (
                "High Risk"
                if request_count >= high_threshold
                else "Medium Risk"
                if request_count >= medium_threshold
                else "Low Risk"
            )

            country_flag = entry.get("country_flag", "🏳️")
            country = entry.get("country", "Unknown")
            asn = entry.get("asn", "Unknown")
            isp = entry.get("isp", "Unknown")

            enriched_ip = (
                f"{country_flag} {entry.get('ip', 'Unknown')}"
            )

            provider_context = f"{asn} • {isp}"

            parsed_logs.append({
                "Timestamp": entry.get("timestamp", "Unknown"),
                "Source IP": enriched_ip,
                "Country": country,
                "ASN / Provider": provider_context,
                "Requests": request_count,
                "Traffic State": traffic_state,
                "Classification": behaviour_classification,
                "IP Reputation": ip_reputation
            })

        logs_df = pd.DataFrame(parsed_logs)

        if ip_filter:
            logs_df = logs_df[
                logs_df["Source IP"].astype(str).str.contains(
                    ip_filter,
                    case=False,
                    na=False
                )
            ]

        if time_range_filter != "All Activity":

            current_time = datetime.now()

            if time_range_filter == "Last 15 Minutes":
                cutoff_time = current_time - timedelta(minutes=15)

            elif time_range_filter == "Last Hour":
                cutoff_time = current_time - timedelta(hours=1)

            else:
                cutoff_time = current_time - timedelta(hours=24)

            filtered_logs = []

            for row in logs_df.to_dict("records"):

                timestamp_value = str(row.get("Timestamp", ""))

                try:
                    parsed_timestamp = pd.to_datetime(timestamp_value)

                    if parsed_timestamp >= cutoff_time:
                        filtered_logs.append(row)

                except:
                    filtered_logs.append(row)

            logs_df = pd.DataFrame(filtered_logs)


        if classification_filter != "All Classifications":
            logs_df = logs_df[
                logs_df["Classification"] == classification_filter
            ]

        if not logs_df.empty:
            logs_df = logs_df.sort_values(
                by="Requests",
                ascending=False
            )

        logs_header_col1, logs_header_col2 = st.columns([8, 2])

        with logs_header_col1:
            st.markdown(
                f"## Parsed Traffic Logs <span style='font-size:14px; opacity:0.7;'>({len(logs_df)} records)</span>",
                unsafe_allow_html=True
            )

        with logs_header_col2:
            st.download_button(
                label="Export Logs CSV",
                data=logs_df.to_csv(index=False),
                file_name="nora_parsed_logs.csv",
                mime="text/csv",
                use_container_width=True,
                key="export_logs_csv"
            )

        st.dataframe(
            logs_df,
            use_container_width=True,
            height=400
        )

        st.markdown("<br>", unsafe_allow_html=True)

        with st.expander("Selected IP Intelligence", expanded=False):

            selected_ip = st.selectbox(
                "Lookup IP Intelligence",
                options=logs_df["Source IP"].tolist()
                if not logs_df.empty
                else ["No IPs Available"],
                key="log_explorer_ip_lookup"
            )

            selected_row = logs_df[
                logs_df["Source IP"] == selected_ip
            ]

            if not selected_row.empty:

                selected_record = selected_row.iloc[0]

                with st.container():

                    st.markdown("**IP Address**")
                    st.caption(selected_record.get("Source IP", "Unknown"))

                    st.markdown("**ASN / Provider**")
                    st.caption(selected_record.get("ASN / Provider", "Unknown"))

                    st.markdown("**Traffic State**")
                    st.caption(selected_record.get("Traffic State", "Unknown"))

                    st.markdown("**IP Reputation**")
                    st.caption(selected_record.get("IP Reputation", "Unknown"))

                    intel_col1, intel_col2 = st.columns(2)

                    with intel_col1:

                        st.markdown("**Country**")
                        st.caption(selected_record.get("Country", "Unknown"))

                        st.markdown("**Requests**")
                        st.caption(selected_record.get("Requests", "0"))

                    with intel_col2:

                        st.markdown("**Classification**")
                        st.caption(selected_record.get("Classification", "Unknown"))

                    st.markdown("---")

                    st.markdown("**Operational Summary**")

                    st.caption(
                        "Investigation workflow active. Future phases will integrate behavioural timelines, correlated attack intelligence, reputation scoring, anomaly memory, and external threat intelligence enrichment."
                    )

    st.markdown("<br>", unsafe_allow_html=True)

    alerts_container = st.container(border=True)

    with alerts_container:

        enriched_alerts = []

        for alert in alerts:

            confidence_score = alert.get("confidence", 0)

            try:
                confidence_score = int(
                    str(confidence_score).replace("%", "")
                )
            except:
                confidence_score = 0

            severity_level = str(
                alert.get("severity", "LOW")
            ).upper()

            behaviour_type = (
                "Distributed Burst Activity"
                if severity_level == "HIGH"
                else "Elevated Behavioural Activity"
                if severity_level == "MEDIUM"
                else "Passive Reconnaissance"
            )

            operational_state = (
                "Escalated Investigation"
                if confidence_score >= 85
                else "Active Investigation"
                if confidence_score >= 60
                else "Monitoring"
            )

            reputation_state = (
                "High Risk"
                if confidence_score >= 85
                else "Medium Risk"
                if confidence_score >= 60
                else "Low Risk"
            )

            country_flag = alert.get("country_flag", "🏳️")
            country = alert.get("country", "Unknown")
            asn = alert.get("asn", "Unknown")
            isp = alert.get("isp", "Unknown")
            threat_level = alert.get("threat_level", "Unknown")

            enriched_ip = (
                f"{country_flag} {alert.get('ip', 'Unknown')}"
            )

            provider_context = f"{asn} • {isp}"

            enriched_alerts.append({
                "Timestamp": alert.get("timestamp", "Unknown"),
                "Source IP": enriched_ip,
                "Country": country,
                "ASN / Provider": provider_context,
                "Severity": severity_level,
                "Confidence": f"{confidence_score}%",
                "Threat Level": threat_level,
                "Behaviour Type": behaviour_type,
                "Operational State": operational_state,
                "Reputation": reputation_state
            })

        alerts_df = pd.DataFrame(enriched_alerts)

        if severity_filter != "All Severities":
            alerts_df = alerts_df[
                alerts_df["Severity"] == severity_filter
            ]

        if not alerts_df.empty:
            alerts_df = alerts_df.sort_values(
                by="Severity",
                ascending=False
            )

        alerts_header_col1, alerts_header_col2, alerts_header_col3 = st.columns([6, 2, 2])

        with alerts_header_col1:
            st.markdown(
                f"## Detection Events / Anomalies <span style='font-size:14px; opacity:0.7;'>({len(alerts_df)} records)</span>",
                unsafe_allow_html=True
            )

        with alerts_header_col2:
            st.download_button(
                label="Export CSV",
                data=alerts_df.to_csv(index=False),
                file_name="nora_detection_events.csv",
                mime="text/csv",
                use_container_width=True,
                key="export_detection_csv"
            )

        with alerts_header_col3:
            st.download_button(
                label="Export JSON",
                data=alerts_df.to_json(orient="records"),
                file_name="nora_detection_events.json",
                mime="application/json",
                use_container_width=True,
                key="export_detection_json"
            )

        st.dataframe(
            alerts_df,
            use_container_width=True,
            height=320
        )
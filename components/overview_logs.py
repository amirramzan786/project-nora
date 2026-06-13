

import streamlit as st

from src.icons import get_icon


def render_overview_logs(alerts, normal_activity, anomalies):
    """Render Overview traffic log preview and security alert preview."""

    log_container = st.container(border=True)

    with log_container:
        title_left, title_right = st.columns([1, 1], gap="medium")

        with title_left:
            st.markdown(
                f"""
                <div class='nora-section-title'>
                    {get_icon('search')}
                    <span>Traffic Log Analysis</span>
                </div>
                """,
                unsafe_allow_html=True
            )

        with title_right:
            st.markdown(
                f"""
                <div class='nora-section-title'>
                    {get_icon('shield_alert')}
                    <span>Security Alerts</span>
                </div>
                """,
                unsafe_allow_html=True
            )

        row1_left, row1_right = st.columns([1, 1], gap="medium")

        with row1_left:
            if normal_activity:
                for entry in normal_activity[:3]:
                    st.markdown(f"""
<div class='nora-activity-card nora-activity-inline-card'>
    <span class='nora-inline-ip'>{entry['ip']}</span>
    <span class='nora-inline-time'>{entry['timestamp']}</span>
    <span class='nora-inline-requests'>Requests: {entry['count']}</span>
</div>
""", unsafe_allow_html=True)

                remaining_logs = max(len(normal_activity) - 3, 0)

                if remaining_logs > 0:
                    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

                    log_button_label = (
                        f"View {remaining_logs} More Log"
                        if remaining_logs == 1
                        else f"View {remaining_logs} More Logs"
                    )

                    if st.button(log_button_label, key="open_log_explorer"):
                        st.session_state.active_page = "log_explorer"
                        st.query_params["page"] = "log_explorer"
                        st.rerun()

            else:
                st.success("No normal traffic recorded")

        with row1_right:
            combined_alerts = []

            if alerts:
                for alert in alerts:
                    request_count = int(alert.get("count", 0))

                    if request_count <= 2:
                        continue

                    if request_count >= 300:
                        severity = "CRITICAL"
                        severity_class = "critical"
                        analyst_state = "Immediate investigation recommended"
                    elif request_count >= 120:
                        severity = "HIGH"
                        severity_class = "high"
                        analyst_state = "ML-assisted threat investigation recommended"
                    elif request_count >= 45:
                        severity = "MEDIUM"
                        severity_class = "medium"
                        analyst_state = "Behavioural anomaly under investigation"
                    else:
                        severity = "LOW"
                        severity_class = "low"
                        analyst_state = "Passive telemetry monitoring active"

                    combined_alerts.append({
                        "ip": alert.get("ip", "Unknown"),
                        "count": request_count,
                        "severity": severity,
                        "severity_class": severity_class,
                        "analyst_state": analyst_state,
                        "source": "Rule-Based Detection"
                    })

            if anomalies:
                for anomaly in anomalies:
                    request_count = int(anomaly.get("requests", 0))

                    if request_count <= 2:
                        continue

                    top_ip = "Unknown"

                    if anomaly.get("top_ips") and len(anomaly["top_ips"]) > 0:
                        top_ip = anomaly["top_ips"][0].get("ip", "Unknown")

                    anomaly_severity = str(anomaly.get("severity", "LOW")).upper()

                    severity_map = {
                        "HIGH": {
                            "severity_class": "high",
                            "analyst_state": "ML-assisted threat investigation recommended"
                        },
                        "MEDIUM": {
                            "severity_class": "medium",
                            "analyst_state": "Anomalous behavioural pattern under review"
                        },
                        "LOW": {
                            "severity_class": "low",
                            "analyst_state": "Passive anomaly monitoring active"
                        }
                    }

                    mapped = severity_map.get(anomaly_severity, severity_map["LOW"])

                    combined_alerts.append({
                        "ip": top_ip,
                        "count": request_count,
                        "severity": anomaly_severity,
                        "severity_class": mapped["severity_class"],
                        "analyst_state": mapped["analyst_state"],
                        "source": "ML Detection Engine"
                    })

            severity_priority = {
                "CRITICAL": 4,
                "HIGH": 3,
                "MEDIUM": 2,
                "LOW": 1
            }

            combined_alerts = sorted(
                combined_alerts,
                key=lambda x: (
                    severity_priority.get(x["severity"], 0),
                    x["count"]
                ),
                reverse=True
            )

            visible_alerts_limit = 4
            visible_alerts = combined_alerts[:visible_alerts_limit]

            if visible_alerts:
                for alert in visible_alerts:
                    severity_colour = {
                        "critical": "#FCA5A5",
                        "high": "#FCA5A5",
                        "medium": "#FCD34D",
                        "low": "#86EFAC"
                    }.get(alert["severity_class"], "#CBD5E1")

                    alert_html = f"""
<div class='nora-activity-card nora-alert-inline-card nora-alert-{alert['severity_class']}'>
    <div style='display:flex;justify-content:space-between;align-items:center;gap:12px;'>
        <div>
            <div style='font-size:13px;font-weight:600;color:{severity_colour};letter-spacing:0.04em;'>
                {alert['severity']} PRIORITY
            </div>
            <div style='font-size:13px;color:#F8FAFC;margin-top:4px;'>
                {alert['count']} requests detected from {alert['ip']}
            </div>
        </div>
    </div>
</div>
"""

                    st.markdown(alert_html, unsafe_allow_html=True)

                remaining_alerts = max(
                    len(combined_alerts) - visible_alerts_limit,
                    0
                )

                if remaining_alerts > 0:
                    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

                    button_label = (
                        f"View {remaining_alerts} More Alert"
                        if remaining_alerts == 1
                        else f"View {remaining_alerts} More Alerts"
                    )

                    if st.button(button_label, key="open_log_explorer_alerts"):
                        st.session_state.active_page = "log_explorer"
                        st.query_params["page"] = "log_explorer"
                        st.rerun()

            else:
                st.success("No suspicious activity detected")
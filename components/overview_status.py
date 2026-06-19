import streamlit as st

from src.icons import get_icon


def render_overview_status(ip_totals, overall_severity="LOW", anomaly_count=0):
    """Render the Overview system status banner."""

    status_col = st.container()

    with status_col:
        if ip_totals:
            max_requests = max(ip_totals.values())

            severity = str(overall_severity).upper()

            if severity == "HIGH" and anomaly_count > 0:
                st.markdown(
                    f"""
                    <div class='nora-alert-banner danger'>
                        <div class='nora-alert-icon'>{get_icon("shield_alert")}</div>
                        <div>
                            <div class='nora-alert-title'>DDoS Attack Detected</div>
                            <div class='nora-alert-sub'>Immediate attention required</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            elif severity == "MEDIUM":
                st.markdown(
                    f"""
                    <div class='nora-alert-banner warning'>
                        <div class='nora-alert-icon'>{get_icon("alert_triangle")}</div>
                        <div>
                            <div class='nora-alert-title'>Suspicious Traffic Detected</div>
                            <div class='nora-alert-sub'>Monitoring and investigation advised</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            else:
                st.markdown(
                    f"""
                    <div class='nora-alert-banner success'>
                        <div class='nora-alert-icon'>{get_icon("check_circle")}</div>
                        <div>
                            <div class='nora-alert-title'>Normal Traffic Conditions</div>
                            <div class='nora-alert-sub'>No active denial-of-service indicators detected</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
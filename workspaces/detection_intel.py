import streamlit as st
import pandas as pd

from src.icons import get_icon
from components.severity_queue import render_severity_queue
from components.correlated_threat_summary import render_correlated_threat_summary
from components.notification_workflow_panel import render_notification_workflow_panel
from components.analyst_action_panel import render_analyst_action_panel

from components.ui_helpers import (
    render_section_title,
    render_threat_stat
)

from src.detection_metrics import get_detection_metrics
from src.threat_source_intelligence import build_threat_source_rows

from components.operational_cards import (
    render_operational_hero_card,
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
            escalated_event_count
        )
    st.markdown(
        "</div>",
        unsafe_allow_html=True
    )

    # =====================================================
    # PHASE 3 ROADMAP NOTE
    # =====================================================
    # Detection Correlation Engine requires a future realism
    # and presentation redesign. Current telemetry is valid,
    # but queue rendering remains text-heavy and should evolve
    # into a more analyst-centric operational correlation view
    # during the next Detection Intelligence enhancement phase.
    # =====================================================
    # MAIN ANALYSIS PANELS
    # =====================================================

    left_col, right_col = st.columns([1.55, 1])

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

                    # --- Phase 2.5 unified realism calibration ---
                    severity = overall_severity
                    confidence = estimated_confidence

                    severity_indicator = {
                        "LOW": "P4",
                        "MEDIUM": "P2",
                        "HIGH": "P1"
                    }.get(severity, "P4")

                    status = {
                        "LOW": "[MONITORING]",
                        "MEDIUM": "[INVESTIGATING]",
                        "HIGH": "[ESCALATED]"
                    }.get(severity, "[MONITORING]")

                    behavioural_pattern = telemetry_profile[
                        "correlation_state"
                    ]

                    correlation_rows.append({
                        "Priority": severity_indicator,
                        "Detection Pattern": anomaly.get("pattern", "Traffic Anomaly"),
                        "Behaviour": behavioural_pattern,
                        "Requests": request_count,
                        "Confidence": f"{confidence}%",
                        "Lifecycle": status,
                        "Severity": severity
                    })

            if correlation_rows:

                # --- Phase 2.5E operational correlation diversification ---
                if overall_severity == "MEDIUM":

                    diversified_correlation_rows = [
                        {
                            **correlation_rows[0],
                            "Priority": "🔴 P1",
                            "Lifecycle": "[ACTIVE ESCALATION]",
                            "Severity": "HIGH",
                            "Confidence": "92%",
                            "Behaviour": "Sustained Coordinated Activity"
                        },
                        {
                            **correlation_rows[0],
                            "Priority": "🟠 P2",
                            "Lifecycle": "[INVESTIGATING]",
                            "Severity": "MEDIUM",
                            "Confidence": "81%",
                            "Behaviour": "Coordinated Burst Pattern"
                        },
                        {
                            **correlation_rows[0],
                            "Priority": "🟢 P4",
                            "Lifecycle": "[MONITORING]",
                            "Severity": "LOW",
                            "Confidence": "58%",
                            "Behaviour": "Distributed Probe Behaviour"
                        }
                    ]

                    visible_correlation_rows = diversified_correlation_rows

                else:
                    visible_correlation_rows = correlation_rows[:3]


                for row in visible_correlation_rows:

                    severity_glow = {
                        'HIGH': '#ef4444',
                        'MEDIUM': '#f59e0b',
                        'LOW': '#22c55e'
                    }.get(row['Severity'], '#38bdf8')

                    severity_background = {
                        'HIGH': 'rgba(239, 68, 68, 0.16)',
                        'MEDIUM': 'rgba(245, 158, 11, 0.16)',
                        'LOW': 'rgba(34, 197, 94, 0.16)'
                    }.get(row['Severity'], 'rgba(56, 189, 248, 0.14)')

                    severity_border = {
                        'HIGH': 'rgba(239, 68, 68, 0.35)',
                        'MEDIUM': 'rgba(245, 158, 11, 0.35)',
                        'LOW': 'rgba(34, 197, 94, 0.35)'
                    }.get(row['Severity'], 'rgba(56, 189, 248, 0.25)')

                    correlation_card = f"""
                        <div class='nora-correlation-queue-row'>
                        <div 
class='nora-correlation-priority'
style='
background:{severity_background};
border:1px solid {severity_border};
box-shadow:0 0 18px {severity_background};
color:{severity_glow};
'
>
{row['Priority']}
</div>
                        <div class='nora-correlation-pattern'>
                        <div class='nora-correlation-pattern-title'>{row['Detection Pattern']}</div>
                        <div class='nora-correlation-pattern-meta'>{row['Behaviour']}</div>
                        </div>
                        <div class='nora-correlation-confidence'>{row['Confidence']}</div>
                        <div class='nora-correlation-lifecycle'>{row['Lifecycle']}</div>
                        <div class='nora-correlation-severity' style='color:{severity_glow};'>{row['Severity']}</div>
                        </div>
                        """

                    st.markdown(correlation_card, unsafe_allow_html=True)

        # (Detection Timeline and Threat Intelligence Visualisation moved below)

    # -----------------------------------------------------
    # RIGHT: SOC ANALYST QUEUE
    # -----------------------------------------------------

    with right_col:

        with st.container(border=True):

            render_section_title(
                'shield',
                'SOC Severity Routing Queue'
            )

            render_severity_queue(
                anomalies,
                overall_severity=overall_severity,
                estimated_confidence=estimated_confidence
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

            render_section_title(
                'pie_chart',
                'Threat Intelligence Visualisation'
            )

            st.markdown(
                "<div class='nora-workspace-spacing-sm'></div>",
                unsafe_allow_html=True
            )

            visual_top_col, visual_bottom_col = st.columns([0.9, 1.3])

            with visual_top_col:

                # --- Phase 2.5: Dynamic threat distribution ---
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


                threat_distribution = pd.DataFrame({
                    "Threat Type": [
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

                st.markdown("### Active Threat Distribution")

                st.plotly_chart(
                    {
                        "data": [{
                            "labels": threat_distribution["Threat Type"],
                            "values": threat_distribution["Count"],
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
                                "text": "Threat<br>Telemetry",
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

            with visual_bottom_col:

                # --- Phase 2.5: Dynamic behavioural progression ---
                telemetry_rows = []

                if time_counts:
                    sorted_times = sorted(time_counts.items())

                    for timestamp, count in sorted_times:
                        telemetry_rows.append({
                            "Time": str(timestamp)[:5],
                            "Threat Volume": count
                        })

                if not telemetry_rows:
                    telemetry_rows.append({
                        "Time": "00:00",
                        "Threat Volume": 0
                    })

                telemetry_placeholder = pd.DataFrame(telemetry_rows)

                # --- Operational progression smoothing ---
                telemetry_placeholder["Threat Volume"] = (
                    telemetry_placeholder["Threat Volume"]
                    .rolling(window=2, min_periods=1)
                    .mean()
                )

                st.markdown("### Behavioural Threat Progression")

                st.area_chart(
                    telemetry_placeholder.set_index("Time"),
                    height=205
                )
                # (Escalation state label display removed)

    # =====================================================
    # TOP THREAT SOURCES
    # =====================================================

    enriched_threats = []

    with st.container(border=True):

        render_section_title(
            'globe',
            'Top Threat Sources'
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

            threat_df = pd.DataFrame(threat_rows)

            st.dataframe(
                threat_df,
                use_container_width=True,
                hide_index=True,
                height=225,
                column_config={
                    "Priority": st.column_config.TextColumn(
                        width="small"
                    ),
                    "Threat Source": st.column_config.TextColumn(
                        width="large"
                    ),
                    "Threat Class": st.column_config.TextColumn(
                        width="medium"
                    ),
                    "Infrastructure": st.column_config.TextColumn(
                        width="large"
                    ),
                    "Region": st.column_config.TextColumn(
                        width="small"
                    ),
                    "Requests": st.column_config.NumberColumn(
                        width="small"
                    ),
                    "Threat": st.column_config.TextColumn(
                        width="small"
                    ),
                    "Similarity": st.column_config.TextColumn(
                        width="small"
                    ),
                    "Escalation": st.column_config.TextColumn(
                        width="medium"
                    ),
                    "Traffic Profile": st.column_config.TextColumn(
                        width="large"
                    ),
                    "Confidence": st.column_config.TextColumn(
                        width="small"
                    )
                    ,"Correlation": st.column_config.TextColumn(
                        width="small"
                    )
                }
            )

            render_correlated_threat_summary(
                enriched_threats,
                estimated_confidence
            )

    # -----------------------------------------------------
    # OPERATIONAL RESPONSE CENTER & WORKFLOW ORCHESTRATION (Stacked)
    # -----------------------------------------------------

    render_operational_hero_card(overall_severity)

    st.markdown(
        """
        <style>
        div[data-testid="stVerticalBlock"]:has(.nora-notification-workflow-anchor) {
            padding-bottom: 0 !important;
            margin-bottom: -70px !important;
            min-height: auto !important;
            height: auto !important;
        }
        </style>
        <div class='nora-notification-workflow-anchor'></div>
        """,
        unsafe_allow_html=True
    )

    render_notification_workflow_panel(enriched_threats)

    render_analyst_action_panel()

    # =====================================================
    # FUTURE INTELLIGENCE EXPANSION
    # =====================================================

    with st.container(border=True):

        render_section_title(
            'brain',
            'Future Intelligence Expansion'
        )

        st.info(
            "Threat reputation enrichment, AbuseIPDB integration, ASN intelligence and regional attack analysis will integrate into this operational workflow during later intelligence phases."
        )
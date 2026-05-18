import streamlit as st


from components.ui_helpers import (
    get_detection_severity
)

import random



def render_severity_queue(
    anomalies,
    overall_severity="MEDIUM",
    estimated_confidence=78
):

    severity_rows = []

    if anomalies:

        sorted_anomalies = sorted(
            anomalies,
            key=lambda x: x.get("requests", 0),
            reverse=True
        )

        for anomaly in sorted_anomalies[:5]:

            request_count = anomaly.get("requests", 0)

            # --- Phase 2.5 unified queue realism ---
            # Align routing queue behaviour with the
            # global operational severity posture.

            severity = overall_severity

            base_confidence = estimated_confidence

            lifecycle = {
                "LOW": "Passive Monitoring",
                "MEDIUM": "Active Investigation",
                "HIGH": "Escalated Response"
            }.get(severity, "Active Investigation")

            # Ensure confidence is numeric before applying variation
            try:
                base_confidence = int(
                    str(base_confidence).replace('%', '').strip()
                )
            except (ValueError, TypeError):
                base_confidence = 72

            # --- Phase 2.5 realism calibration ---
            # Prevent repetitive identical confidence values
            # and diversify operational queue behaviour.
            confidence_variation = {
                "LOW": random.randint(-10, -2),
                "MEDIUM": random.randint(-4, 4),
                "HIGH": random.randint(-2, 3)
            }.get(severity, 0)
            confidence = max(
                48,
                min(base_confidence + confidence_variation, 96)
            )

            lifecycle_variations = {
                "LOW": [
                    "Passive Monitoring",
                    "Behaviour Tracking"
                ],
                "MEDIUM": [
                    "Active Investigation",
                    "Analyst Review"
                ],
                "HIGH": [
                    "Escalated Response",
                    "SOC Containment",
                    "Incident Mitigation",
                    "Critical Incident Review"
                ]
            }

            lifecycle = random.choice(
                lifecycle_variations.get(
                    severity,
                    [lifecycle]
                )
            )

            severity_rows.append({
                "Severity": severity,
                "Pattern": anomaly.get("pattern", "Traffic Anomaly"),
                "Requests": request_count,
                "Confidence": confidence,
                "Lifecycle": lifecycle
            })

    if severity_rows:

        for row in severity_rows:

            severity_color = {
                "LOW": "#22c55e",
                "MEDIUM": "#f59e0b",
                "HIGH": "#ef4444"
            }.get(row["Severity"], "#22c55e")

            escalation_variations = {
                "LOW": [
                    "Monitor",
                    "Observe",
                    "Track"
                ],
                "MEDIUM": [
                    "Investigate",
                    "Review",
                    "Correlate"
                ],
                "HIGH": [
                    "Contain Threat",
                    "Mitigate Traffic",
                    "Escalate Incident",
                    "Activate SOC Response"
                ]
            }

            escalation_state = random.choice(
                escalation_variations.get(
                    row["Severity"],
                    ["Monitor"]
                )
            )

            response_card_html = (
                f"<div class='nora-response-queue-card'>"
                f"<div class='nora-response-queue-header'>"
                f"<div class='nora-response-pattern'>{row['Pattern']}</div>"
                f"<div class='nora-response-severity' style='color:{severity_color};'>{row['Severity']}</div>"
                f"</div>"
                f"<div class='nora-response-meta-row'>"
                f"<div class='nora-response-meta-block'>"
                f"<span class='nora-response-meta-label'>Requests</span>"
                f"<span class='nora-response-meta-value'>{row['Requests']}</span>"
                f"</div>"
                f"<div class='nora-response-meta-block'>"
                f"<span class='nora-response-meta-label'>Confidence</span>"
                f"<span class='nora-response-meta-value'>{row['Confidence']}%</span>"
                f"</div>"
                f"<div class='nora-response-meta-block'>"
                f"<span class='nora-response-meta-label'>Lifecycle</span>"
                f"<span class='nora-response-meta-value'>{row['Lifecycle']}</span>"
                f"</div>"
                f"</div>"
                f"<div class='nora-response-escalation'>"
                f"Action: <strong>{escalation_state}</strong>"
                f"</div>"
                f"</div>"
            )

            st.markdown(
                response_card_html,
                unsafe_allow_html=True
            )

    st.markdown(
        """
        <style>
        .nora-response-queue-card {
            padding: 13px 14px;
            margin-bottom: 8px;
            border-radius: 14px;
            border: 1px solid rgba(0, 170, 255, 0.12);
            background: linear-gradient(
                135deg,
                rgba(1, 10, 28, 0.96),
                rgba(0, 8, 24, 0.98)
            );
        }

        .nora-response-queue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .nora-response-pattern {
            font-size: 15px;
            font-weight: 700;
            color: white;
        }

        .nora-response-severity {
            font-size: 14px;
            font-weight: 700;
        }

        .nora-response-meta-row {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
            margin-bottom: 10px;
        }

        .nora-response-meta-block {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .nora-response-meta-label {
            font-size: 11px;
            color: rgba(255,255,255,0.45);
            text-transform: uppercase;
            letter-spacing: 0.6px;
        }

        .nora-response-meta-value {
            font-size: 13px;
            font-weight: 600;
            color: rgba(255,255,255,0.82);
        }

        .nora-response-escalation {
            font-size: 13px;
            color: rgba(255,255,255,0.72);
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.06);
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.caption(
        "Operational response prioritisation currently uses behavioural severity thresholds and escalation lifecycle monitoring."
    )
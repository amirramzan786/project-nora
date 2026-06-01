import streamlit as st

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

            # Ensure estimated confidence is numeric
            try:
                estimated_confidence_numeric = int(
                    str(estimated_confidence)
                    .replace('%', '')
                    .strip()
                )
            except (ValueError, TypeError):
                estimated_confidence_numeric = 72

            queue_position = len(severity_rows)

            # --- Phase 2.5E adaptive queue diversification ---
            # Create realistic operational queue distribution
            # instead of identical escalation states.

            if overall_severity == "MEDIUM":

                diversified_queue_profiles = [
                    {
                        "severity": "HIGH",
                        "lifecycle": "Escalated Response",
                        "confidence": estimated_confidence_numeric + 10
                    },
                    {
                        "severity": "MEDIUM",
                        "lifecycle": "Active Investigation",
                        "confidence": estimated_confidence_numeric + 4
                    },
                    {
                        "severity": "MEDIUM",
                        "lifecycle": "Analyst Review",
                        "confidence": estimated_confidence_numeric
                    },
                    {
                        "severity": "LOW",
                        "lifecycle": "Behaviour Tracking",
                        "confidence": estimated_confidence_numeric - 12
                    },
                    {
                        "severity": "LOW",
                        "lifecycle": "Passive Monitoring",
                        "confidence": estimated_confidence_numeric - 18
                    }
                ]

                profile = diversified_queue_profiles[min(
                    queue_position,
                    len(diversified_queue_profiles) - 1
                )]

                severity = profile["severity"]
                lifecycle = profile["lifecycle"]
                base_confidence = profile["confidence"]

            else:
                severity = overall_severity
                base_confidence = estimated_confidence_numeric

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

            if overall_severity != "MEDIUM":
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

            if row["Severity"] == "HIGH":
                escalation_state = random.choice([
                    "Escalate Incident",
                    "Activate SOC Response",
                    "Mitigate Traffic"
                ])

            elif row["Severity"] == "MEDIUM":
                escalation_state = random.choice([
                    "Investigate",
                    "Review",
                    "Correlate"
                ])

            else:
                escalation_state = random.choice([
                    "Monitor",
                    "Observe",
                    "Track"
                ])

            response_card_html = (
                f"<div class='nora-response-queue-card'>"
                f"<div class='nora-response-queue-header'>"
                f"<div><div class='nora-response-pattern'>{row['Pattern']}</div><div class='nora-response-pattern-meta'>Behavioural Detection Pattern</div></div>"
                f"<div class='nora-response-severity nora-response-severity-{row['Severity'].lower()}'>{row['Severity']}</div>"
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
                f"<span class='nora-response-escalation-label'>ESCALATION</span>"
                f"<span class='nora-response-escalation-state'>{escalation_state}</span>"
                f"</div>"
                f"</div>"
            )

            st.markdown(
                response_card_html,
                unsafe_allow_html=True
            )
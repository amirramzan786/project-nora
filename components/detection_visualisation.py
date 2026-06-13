import streamlit as st
import pandas as pd

from src.icons import get_icon


def render_detection_visualisation(
    similarity_score,
    historical_session_matches,
    time_counts,
    avg_requests,
    anomalies,
    source_concentration_score,
    request_burst_score,
    historical_similarity_score,
    adaptive_reinforcement_score,
    adaptive_confidence,
):
    """Render Detection Intelligence visualisation charts."""

    with st.container(border=True):
        st.markdown(
            (
                "<div class='nora-detection-visual-marker'></div>"
                "<div class='nora-detection-visual-header'>"
                "<div class='nora-detection-panel-title'>"
                f"{get_icon('fc_statistics')}"
                "<span>Detection Intelligence Visualisation</span>"
                "</div>"
                "<details class='nora-detection-panel-info'>"
                "<summary class='nora-detection-info-trigger'>i</summary>"
                "<div class='nora-detection-info-content'>Visualises severity distribution, behavioural activity progression and anomaly score movement using the current detection telemetry.</div>"
                "</details>"
                "</div>"
                "<div class='nora-detection-panel-divider'></div>"
            ),
            unsafe_allow_html=True
        )

        visual_col1, visual_col2, visual_col3 = st.columns([1, 1.4, 1])

        with visual_col1:
            st.markdown("### Pattern Similarity Analysis")

            similarity_rows = []

            similarity_rows.append({
                "Pattern": "Current Detection",
                "Similarity": similarity_score
            })

            if historical_session_matches:
                for match in historical_session_matches[:3]:
                    similarity_rows.append({
                        "Pattern": f"Session {match['session_id'][:6]}",
                        "Similarity": match["similarity_score"]
                    })
            else:
                similarity_rows.extend([
                    {
                        "Pattern": "Burst Attack",
                        "Similarity": max(similarity_score - 8, 0)
                    },
                    {
                        "Pattern": "Sustained Flood",
                        "Similarity": max(similarity_score - 22, 0)
                    },
                    {
                        "Pattern": "Baseline Activity",
                        "Similarity": max(similarity_score - 45, 0)
                    }
                ])

            similarity_df = pd.DataFrame(similarity_rows)

            st.bar_chart(
                similarity_df.set_index("Pattern"),
                height=205
            )

        with visual_col2:
            telemetry_rows = []

            if time_counts:
                sorted_times = sorted(time_counts.items())
                baseline_volume = avg_requests if avg_requests > 0 else 1

                for timestamp, count in sorted_times:
                    telemetry_rows.append({
                        "Time": str(timestamp)[:5],
                        "Observed Traffic": count,
                        "Baseline Behaviour": baseline_volume
                    })

            if not telemetry_rows:
                telemetry_rows.append({
                    "Time": "00:00",
                    "Observed Traffic": 0,
                    "Baseline Behaviour": 0
                })

            telemetry_df = pd.DataFrame(telemetry_rows)

            st.markdown("### Behavioural Detection Timeline")

            st.line_chart(
                telemetry_df.set_index("Time"),
                height=205
            )

            anomaly_points = len(anomalies)

            st.caption(
                f"Observed {anomaly_points} anomalous events against behavioural baseline"
            )

        with visual_col3:
            st.markdown("### Confidence Evolution")

            confidence_breakdown_df = pd.DataFrame([
                {
                    "Signal": "Source Concentration",
                    "Contribution": source_concentration_score
                },
                {
                    "Signal": "Request Burst Activity",
                    "Contribution": request_burst_score
                },
                {
                    "Signal": "Historical Similarity",
                    "Contribution": historical_similarity_score
                },
                {
                    "Signal": "Memory Reinforcement",
                    "Contribution": adaptive_reinforcement_score
                },
                {
                    "Signal": "Final Confidence",
                    "Contribution": adaptive_confidence
                }
            ])

            st.bar_chart(
                confidence_breakdown_df.set_index("Signal"),
                height=205
            )

            st.caption(
                f"Adaptive Confidence: {adaptive_confidence}% | Historical reinforcement: +{adaptive_reinforcement_score}%"
            )
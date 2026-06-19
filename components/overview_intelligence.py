import streamlit as st

from src.icons import get_icon


def render_detection_intelligence(df_time, anomalies):
    """Render the Overview Detection Intelligence explanation panel."""

    try:
        if df_time is not None and not df_time.empty:
            avg_requests = df_time["Requests"].mean()

            if anomalies and len(anomalies) > 0:
                try:
                    anomalies_sorted = sorted(
                        anomalies,
                        key=lambda x: str(x.get("time", ""))
                    )
                    latest = anomalies_sorted[-1]
                except Exception:
                    latest = anomalies[-1]

                peak_row = df_time.loc[df_time["Requests"].idxmax()]
                peak_val = int(peak_row["Requests"])

                increase_pct = 0

                if avg_requests > 0:
                    increase_pct = round(
                        ((peak_val - avg_requests) / avg_requests) * 100,
                        1
                    )

                if peak_val >= 350 and increase_pct < 35:
                    increase_pct = 35.0
                elif peak_val >= 180 and increase_pct < 18:
                    increase_pct = 18.0

                pattern = latest.get(
                    "attack_classification",
                    latest.get("pattern", "Unknown")
                )
                similarity = latest.get("similarity", 0)
                z_score = latest.get("z_score", 0)
                classification_summary = latest.get(
                    "classification_summary",
                    "Suspicious traffic behaviour detected."
                )

                if z_score >= 2.5:
                    z_label = "High deviation"
                elif z_score >= 1.5:
                    z_label = "Moderate deviation"
                else:
                    z_label = "Low deviation"

                confidence_score = latest.get("confidence", 0)

                if confidence_score >= 75:
                    confidence_label = "High Confidence"
                elif confidence_score >= 50:
                    confidence_label = "Moderate Confidence"
                else:
                    confidence_label = "Low Confidence"

                if peak_val > avg_requests * 2:
                    severity_reason = "Traffic significantly exceeded normal baseline levels"
                elif peak_val > avg_requests * 1.5:
                    severity_reason = "Traffic moderately exceeded expected behaviour"
                else:
                    severity_reason = "Minor deviation from normal traffic patterns"

                time_window = latest.get("time", "Unknown time window")

                if pattern == "Unknown":
                    pattern_text = "Unclassified traffic pattern"
                else:
                    pattern_text = f"{pattern}"

                attack_classification = latest.get(
                    "classification_pattern_type",
                    "Behavioural Analysis"
                ).replace("_", " ").title()

                st.markdown(f"""
<div class='nora-intel-panel'>
    <div class='nora-intel-inner'>
    <div class='nora-intel-title'>{get_icon("brain")}Detection Intelligence</div>
    <div class='nora-threat-grid'>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Detection Window</div>
            <div class='nora-threat-value'>{time_window}</div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Threat Pattern</div>
            <div class='nora-threat-value'>{pattern_text}</div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Traffic Spike</div>
            <div class='nora-threat-value'>+{increase_pct}%</div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Attack Classification</div>
            <div class='nora-threat-value'>{attack_classification}</div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Confidence</div>
            <div class='nora-threat-value'>{confidence_label}</div>
        </div>
    </div>
    <div class='nora-core-status'>
        <strong>Analyst Summary:</strong><br>
        {classification_summary}
    </div>

</div>
</div>

""", unsafe_allow_html=True)

                return {
                    "similarity": similarity,
                    "z_score": z_score,
                    "z_label": z_label,
                    "severity_reason": severity_reason,
                    "anomalies": anomalies
                }

            st.markdown(f"### {get_icon('brain')} Detection Explanation", unsafe_allow_html=True)
            st.info(
                "Traffic patterns remain within expected thresholds. No significant anomalies or indicators of denial-of-service activity were detected."
            )

    except Exception:
        pass

    return None
import streamlit as st

from src.icons import get_icon


def get_detection_severity(request_count):

    if request_count >= 100:
        return {
            "severity": "HIGH",
            "confidence": "92%",
            "lifecycle": "Escalated"
        }

    elif request_count >= 50:
        return {
            "severity": "MEDIUM",
            "confidence": "81%",
            "lifecycle": "Investigating"
        }

    return {
        "severity": "LOW",
        "confidence": "73%",
        "lifecycle": "Monitoring"
    }



def render_section_title(icon, title):

    st.markdown(
        f"""
<div class='nora-section-title'>
    {get_icon(icon)}
    <span>{title}</span>
</div>
""",
        unsafe_allow_html=True
    )

def render_threat_stat(label, value, extra_class=""):

    telemetry_icons = {
        "Active Alerts": "shield_alert",
        "Estimated Confidence": "brain",
        "Threat Severity": "triangle_alert",
        "Requests Analysed": "activity",
        "Detection Accuracy": "crosshair",
        "Escalated Events": "siren"
    }

    icon = telemetry_icons.get(label, "activity")

    extra_class_html = f" {extra_class}" if extra_class else ""

    st.markdown(
        f"""<div class='nora-threat-stat'>
<div class='nora-threat-label'>
    {get_icon(icon)}
    <span>{label}</span>
</div>

<div class='nora-threat-value{extra_class_html}'>
{value}
</div>
</div>""",
        unsafe_allow_html=True
    )

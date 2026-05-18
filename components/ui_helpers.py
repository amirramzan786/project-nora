import streamlit as st

from src.icons import get_icon



def get_detection_severity(
    request_count,
    unique_ips=1,
    anomaly_count=0,
    avg_requests=0
):

    """
    Phase 2.5 unified severity engine.

    This becomes the authoritative severity model used across:
    - Overview
    - Detection Intelligence
    - Severity Queue
    - Operational escalation workflow
    """

    traffic_ratio = (
        request_count / avg_requests
        if avg_requests and avg_requests > 0 else 1
    )

    threat_score = 0

    if request_count >= 350:
        threat_score += 3
    elif request_count >= 180:
        threat_score += 2
    elif request_count >= 75:
        threat_score += 1

    if unique_ips >= 5:
        threat_score += 2
    elif unique_ips >= 3:
        threat_score += 1

    if anomaly_count >= 3:
        threat_score += 2
    elif anomaly_count >= 1:
        threat_score += 1

    if traffic_ratio >= 1.8:
        threat_score += 2
    elif traffic_ratio >= 1.4:
        threat_score += 1

    # --- Final operational severity ---
    if threat_score >= 7:
        return {
            "severity": "HIGH",
            "confidence": "94%",
            "lifecycle": "Escalated"
        }

    elif threat_score >= 4:
        return {
            "severity": "MEDIUM",
            "confidence": "78%",
            "lifecycle": "Investigating"
        }

    return {
        "severity": "LOW",
        "confidence": "64%",
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


def render_workspace_header(icon, title, description):

    st.markdown(
        f"""
<div class='nora-workspace-card'>
    <div class='nora-section-title'>
        {get_icon(icon)}
        <span>{title}</span>
    </div>

    <div class='nora-workspace-description'>
        {description}
    </div>
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

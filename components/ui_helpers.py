import streamlit as st

from src.icons import get_icon

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
<div class='nora-threat-label nora-threat-label-header'>
    <span class='nora-threat-label-icon'>{get_icon(icon)}</span>
    <span class='nora-threat-label-text'>{label}</span>
</div>

<div class='nora-threat-value{extra_class_html}'>
{value}
</div>
</div>""",
        unsafe_allow_html=True
    )

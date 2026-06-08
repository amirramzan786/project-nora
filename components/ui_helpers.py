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

def render_workspace_header(
    icon,
    title,
    description,
    dataset_mode=None,
    dataset_name=None,
    on_reset_dataset=None,
    reset_key=None,
):
    """Render a workspace header with optional active-dataset context."""

    show_dataset_status = dataset_mode in {"sample", "upload"}

    if not show_dataset_status:
        st.html(
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
"""
        )
        return

    header_col, status_col, action_col = st.columns(
        [6.2, 2.4, 0.35],
        gap="small",
        vertical_alignment="center",
    )

    with header_col:
        st.html(
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
"""
        )

    with status_col:
        active_name = dataset_name or "sample.log"
        status_text = (
            f"Using uploaded log: {active_name}"
            if dataset_mode == "upload"
            else "Using sample log dataset"
        )

        st.html(
            f"""
<div class='nora-live-status'>
    <div class='nora-live-dot'></div>
    <span>{status_text}</span>
</div>
"""
        )

    with action_col:
        if dataset_mode == "upload" and on_reset_dataset is not None:
            st.button(
                "×",
                key=reset_key or f"reset_dataset_{title.lower().replace(' ', '_')}",
                help="Stop using the uploaded log and return to the sample dataset",
                on_click=on_reset_dataset,
            )

def render_threat_stat(label, value, extra_class="", icon_key=None):

    telemetry_icons = {
        "Active Alerts": "shield_alert",
        "Estimated Confidence": "brain",
        "Threat Severity": "triangle_alert",
        "Requests Analysed": "activity",
        "Detection Accuracy": "crosshair",
        "Escalated Events": "siren"
    }

    icon = icon_key if icon_key else telemetry_icons.get(label, "activity")

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

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
    """Render a reusable N.O.R.A workspace header."""

    show_dataset_status = dataset_mode in {"sample", "upload"}
    active_name = dataset_name or "sample.log"

    dataset_label = (
        f"Uploaded Dataset: {active_name}"
        if dataset_mode == "upload"
        else "Sample Dataset: sample.log"
    )

    if not show_dataset_status:
        st.html(
            f"""
<div class='nora-workspace-header'>
    <div class='nora-workspace-header-top'>
        <div class='nora-workspace-header-left'>
            <div class='nora-workspace-header-icon-tile'>
                {get_icon(icon)}
            </div>

            <div class='nora-workspace-header-copy'>
                <div class='nora-workspace-header-title'>
                    <span>{title}</span>
                </div>

                <div class='nora-workspace-header-subtitle'>
                    {description}
                </div>
            </div>
        </div>

        <div class='nora-workspace-header-modules'>
            <div class='nora-workspace-header-module'>
                <div class='nora-workspace-header-module-icon'>
                    {get_icon("dataset")}
                </div>
                <div>
                    <div class='nora-workspace-header-module-label'>Active Workspace</div>
                    <div class='nora-workspace-header-module-value'>Detection Intelligence</div>
                </div>
            </div>

            <div class='nora-workspace-header-module'>
                <div class='nora-workspace-header-module-icon'>⌁</div>
                <div>
                    <div class='nora-workspace-header-module-label'>Analysis</div>
                    <div class='nora-workspace-header-module-value'>Behavioural</div>
                </div>
            </div>

            <div class='nora-workspace-header-module'>
                <div class='nora-workspace-header-module-icon'>∿</div>
                <div>
                    <div class='nora-workspace-header-module-label'>Status</div>
                    <div class='nora-workspace-header-module-value status'>Operational</div>
                </div>
            </div>
        </div>
    </div>
</div>
"""
        )
        return

    reset_html = ""

    if dataset_mode == "upload" and on_reset_dataset is not None:
        current_page = st.query_params.get("page", "overview")

        reset_html = (
            f"<a href='?page={current_page}&reset_dataset=1' class='nora-workspace-header-dataset-close'>×</a>"
        )

    if (
        dataset_mode == "upload"
        and on_reset_dataset is not None
        and st.query_params.get("reset_dataset") == "1"
    ):
        on_reset_dataset()

        if "reset_dataset" in st.query_params:
            del st.query_params["reset_dataset"]

        st.rerun()

    st.html(
        f"""
<div class='nora-workspace-header'>
    <div class='nora-workspace-header-top'>
        <div class='nora-workspace-header-left'>
            <div class='nora-workspace-header-icon-tile'>
                {get_icon(icon)}
            </div>

            <div class='nora-workspace-header-copy'>
                <div class='nora-workspace-header-title'>
                    <span>{title}</span>
                </div>

                <div class='nora-workspace-header-subtitle'>
                    {description}
                </div>
            </div>
        </div>

        <div class='nora-workspace-header-modules'>
            <div class='nora-workspace-header-module'>
                <div class='nora-workspace-header-module-icon'>
                    {get_icon("dataset")}
                </div>
                <div>
                    <div class='nora-workspace-header-module-label'>Dataset</div>
                    <div class='nora-workspace-header-module-value'>
                        {active_name}
                        {reset_html}
                    </div>
                </div>
            </div>

            <div class='nora-workspace-header-module'>
                <div class='nora-workspace-header-module-icon'>
                    {get_icon("workspace")}
                </div>
                <div>
                    <div class='nora-workspace-header-module-label'>Active Workspace</div>
                    <div class='nora-workspace-header-module-value'>{title}</div>
                </div>
            </div>

            <div class='nora-workspace-header-module'>
                <div class='nora-workspace-header-module-icon'>
                    {get_icon("status")}
                </div>
                <div>
                    <div class='nora-workspace-header-module-label'>Status</div>
                    <div class='nora-workspace-header-module-value status'>Under Analysis <span class='nora-workspace-status-dot'></span></div>
                </div>
            </div>
        </div>
    </div>
</div>
"""
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

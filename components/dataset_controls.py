import streamlit as st

from components.ui_helpers import render_workspace_header
from services.app_state import (
    activate_sample_log,
    activate_uploaded_log,
    stop_using_uploaded_log,
)


def render_dataset_controls():
    """Render the Overview dataset selector and upload controls."""

    show_overview_dashboard = True
    current_mode = st.session_state.get("active_log_mode", "sample")
    current_name = st.session_state.get("active_log_name", "sample.log")

    selected_dataset_source = st.query_params.get("dataset_source")

    if selected_dataset_source == "sample":
        if st.session_state.get("active_log_mode") != "sample":
            activate_sample_log()
            st.session_state["log_uploader_version"] += 1
            st.rerun()

        if "dataset_source" in st.query_params:
            del st.query_params["dataset_source"]

    option = (
        "Upload log file"
        if selected_dataset_source == "upload"
        else (
            "Upload log file"
            if st.session_state.get("active_log_mode") == "upload"
            else "Use sample logs"
        )
    )

    dataset_controls_html = f"""
    <div class='nora-dataset-card-controls'>
        <a class='nora-dataset-card-option {'active' if option == 'Use sample logs' else ''}' href='?page=overview&dataset_source=sample'>Sample</a>
        <span class='nora-dataset-card-separator'>|</span>
        <a class='nora-dataset-card-option {'active' if option == 'Upload log file' else ''}' href='?page=overview&dataset_source=upload'>Upload Log File</a>
    </div>
    """

    render_workspace_header(
        icon="shield",
        title="Overview",
        description="Real-time behavioural detection monitoring and threat overview",
        dataset_mode=current_mode,
        dataset_name=current_name,
        dataset_controls_html=dataset_controls_html,
    )

    if option == "Use sample logs":
        if st.session_state.get("active_log_mode") != "sample":
            activate_sample_log()
            st.session_state["log_uploader_version"] += 1
            st.rerun()
    else:
        uploaded_file = st.file_uploader(
            "Please upload a file to begin analysis",
            type=["log", "txt"],
            key=f"log_uploader_{st.session_state['log_uploader_version']}",
        )

        if uploaded_file is not None:
            try:
                activated_new_log = activate_uploaded_log(uploaded_file)

                if activated_new_log:
                    st.rerun()
                else:
                    st.info(f"{uploaded_file.name} is already the active dataset.")
            except Exception as error:
                st.error(f"Unable to analyse the uploaded log: {error}")
        elif st.session_state.get("active_log_mode") != "upload":
            show_overview_dashboard = False

    return show_overview_dashboard
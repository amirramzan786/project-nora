

import datetime

import streamlit as st

from services.app_state import (
    activate_sample_log,
    activate_uploaded_log,
    stop_using_uploaded_log,
)


def get_dashboard_greeting():
    """Return a time-aware greeting for the dashboard header."""

    current_hour = datetime.datetime.now().hour

    if current_hour < 12:
        return "Good morning"

    if current_hour < 18:
        return "Good afternoon"

    return "Good evening"



def render_dataset_controls():
    """Render the Overview dataset selector and upload controls."""

    show_overview_dashboard = True
    greeting = get_dashboard_greeting()

    control_container = st.container(border=True)

    with control_container:
        left_col, mid_col, right_col = st.columns(
            [3, 4, 3],
            gap="large",
            vertical_alignment="center"
        )

        with left_col:
            st.markdown(
                f"""
                <div class='nora-greeting-block'>
                    <div class='nora-greeting-title'>{greeting}, Analyst </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with mid_col:
            st.markdown("<div class='nora-radio-align-wrap'>", unsafe_allow_html=True)

            _, radio_col = st.columns(
                [0.01, 5],
                gap="small",
                vertical_alignment="center"
            )

            with radio_col:
                pending_source_choice = st.session_state.get(
                    "pending_log_source_choice"
                )

                active_source_choice = (
                    "Upload log file"
                    if st.session_state.get("active_log_mode") == "upload"
                    else "Use sample logs"
                )

                desired_source_choice = (
                    pending_source_choice or active_source_choice
                )

                if "log_source_choice_widget" not in st.session_state:
                    st.session_state["log_source_choice_widget"] = desired_source_choice
                elif pending_source_choice:
                    st.session_state["log_source_choice_widget"] = desired_source_choice

                st.session_state["pending_log_source_choice"] = None

                option = st.radio(
                    "Analyse logs",
                    ("Use sample logs", "Upload log file"),
                    horizontal=True,
                    key="log_source_choice_widget",
                    label_visibility="collapsed"
                )

            st.markdown("</div>", unsafe_allow_html=True)

        with right_col:
            current_mode = st.session_state.get("active_log_mode", "sample")
            current_name = st.session_state.get("active_log_name", "sample.log")

            status_box_col, action_box_col = st.columns([5, 1])

            with status_box_col:
                status_text = (
                    f"📤 Using {current_name}"
                    if current_mode == "upload"
                    else "📄 Using sample log dataset"
                )

                st.markdown(
                    f"""
                    <div class='nora-live-status'>
                        <div class='nora-live-dot'></div>
                        <span>{status_text}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with action_box_col:
                if current_mode == "upload":
                    if st.button(
                        "×",
                        key="stop_using_uploaded_log_overview",
                        help="Stop using the uploaded log and return to the sample dataset",
                    ):
                        stop_using_uploaded_log()
                        st.rerun()

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
                    st.session_state["pending_log_source_choice"] = "Upload log file"
                    st.rerun()
                else:
                    st.info(f"{uploaded_file.name} is already the active dataset.")
            except Exception as error:
                st.error(f"Unable to analyse the uploaded log: {error}")
        elif st.session_state.get("active_log_mode") != "upload":
            show_overview_dashboard = False

    return show_overview_dashboard
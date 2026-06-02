import streamlit as st
from workspaces.detection_intel import render_detection_intelligence
from workspaces.adaptive_intel import render_adaptive_intelligence
from workspaces.log_explorer import render_log_explorer
from workspaces.threat_intel import render_threat_intelligence
from components.navigation import render_navigation

from workspaces.overview import render_dashboard

def load_css():
    css_files = [
        "assets/style.css",
        "assets/operational_cards.css",
        "assets/workspace.css",
        "assets/navigation.css",
        "assets/severity_queue.css",
        "assets/threat_intel.css"
    ]

    combined_css = ""

    for css_file in css_files:
        with open(css_file) as f:
            combined_css += f.read() + "\n"

    st.markdown(f"<style>{combined_css}</style>", unsafe_allow_html=True)

st.set_page_config(
    page_title="Project N.O.R.A.",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown(
    """
    <style>
        [data-testid="stSidebar"] {
            display: none !important;
            width: 0 !important;
        }
    </style>
    """,
    unsafe_allow_html=True
)

if "page" not in st.query_params:
    st.query_params["page"] = "overview"

load_css()

from src.log_parser import read_logs


from src.theme import DARK_MODE
import datetime

dark_mode = DARK_MODE

current_hour = datetime.datetime.now().hour

if current_hour < 12:
    greeting = "Good morning"
elif current_hour < 18:
    greeting = "Good afternoon"
else:
    greeting = "Good evening"

shell_sidebar, shell_main = st.columns(
    [0.72, 6.28],
    gap="small"
)

with shell_sidebar:
    active_page = render_navigation()

with shell_main:

    if active_page == "overview":

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

                label_col, radio_col = st.columns(
                    [0.01, 5],
                    gap="small",
                        vertical_alignment="center"
                    )

                with radio_col:
                    option = st.radio(
                        "Analyse logs",
                        ("Use sample logs", "Upload log file"),
                        horizontal=True,
                        label_visibility="collapsed"
                        )

                st.markdown("</div>", unsafe_allow_html=True)

            with right_col:
                status_text = (
                    "📄 Using sample log dataset"
                    if option == "Use sample logs"
                    else "📤 External log upload mode"
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

    else:
        option = "Use sample logs"

    # ---------------- MAIN LOGIC ----------------

    if option == "Upload log file":

        uploaded_file = st.file_uploader(
            "Please upload a file to begin analysis",
            type=["log", "txt"]
        )

        if uploaded_file is not None:

            st.success("File uploaded successfully!")

            file_bytes = uploaded_file.read()

            ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors = read_logs(
                file_content=file_bytes
            )

        else:
            ip_totals = {}
            alerts = []
            normal_activity = []
            time_counts = {}
            anomalies = []
            df_anom = None
            pattern_colors = {}

    else:
        ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors = read_logs(
            "logs/sample.log"
        )


    # ---------------- WORKSPACE ROUTING ----------------

    if active_page == "overview":
        render_dashboard(
            ip_totals,
            alerts,
            normal_activity,
            time_counts,
            anomalies
        )

    elif active_page == "adaptive_intelligence":
        render_adaptive_intelligence()

    elif active_page == "log_explorer":
        render_log_explorer(
            alerts,
            normal_activity
        )

    elif active_page == "threat_intelligence":
        render_threat_intelligence(
            ip_totals,
            alerts,
            normal_activity,
            anomalies
        )

    elif active_page == "network_traffic":
        st.markdown("# Network Traffic Analysis")
        st.info("Network telemetry analysis workspace coming online.")

    elif active_page == "detection_intelligence":
        render_detection_intelligence(
            ip_totals,
            anomalies,
            time_counts,
            alerts
        )

    elif active_page == "detection_performance":
        st.markdown("# Detection Performance Center")
        st.info("Detection evaluation and analyst validation workspace coming online.")
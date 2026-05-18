import streamlit as st
from workspaces.detection_intel import render_detection_intelligence
from workspaces.adaptive_intel import render_adaptive_intelligence

st.set_page_config(
    page_title="Project N.O.R.A.",
    layout="wide",
    initial_sidebar_state="expanded"
)
import base64
from components.sidebar import render_sidebar
from workspaces.overview import render_dashboard

def get_base64_image(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

def load_css():
    with open("assets/style.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

from src.log_parser import read_logs
from src.feedback import save_feedback


from src.theme import DARK_MODE, THEME
import datetime

# --- THEME SYSTEM ---
dark_mode = DARK_MODE

# --- Global Styling ---
load_css()

# --- Navigation System ---
active_page = render_sidebar()

with st.container():

    header_container = st.container(border=True)

    with header_container:
        left_col, right_col = st.columns([7.5, 4.5], vertical_alignment="center")

        with left_col:
            st.markdown("# PROJECT N.O.R.A")

        with right_col:
            st.markdown(
                """
                <div class='nora-analyst-badge'>
                    <span>● N.O.R.A.: NETWORK OPERATIONS & RESPONSE ASSISTANT ●</span>
                </div>
                """,
                unsafe_allow_html=True
            )

# --- GREETING + CONTROL BAR ---
current_hour = datetime.datetime.now().hour

if current_hour < 12:
    greeting = "Good morning"
elif current_hour < 18:
    greeting = "Good afternoon"
else:
    greeting = "Good evening"

control_bg = '#111827' if dark_mode else '#FFFFFF'
control_border = '#334155' if dark_mode else '#E5E7EB'
status_color = '#22C55E'

if active_page == "overview":

    with st.container():

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
        anomalies,
        df_anom,
        pattern_colors
    )

elif active_page == "adaptive_intelligence":
    render_adaptive_intelligence()

elif active_page == "log_explorer":
    st.markdown("# Log Explorer")
    st.info("Expanded log telemetry workspace coming online.")

elif active_page == "threat_intelligence":
    st.markdown("# Threat Intelligence Center")
    st.info("Threat enrichment and reputation analysis workspace coming online.")

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
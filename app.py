from pathlib import Path
import streamlit as st

from components.dataset_controls import render_dataset_controls

def load_css():
    css_files = [
        "assets/style.css",
        "assets/operational_cards.css",
        "assets/workspace.css",
        "assets/navigation.css",
        "assets/threat_intel.css",
        "assets/detection_intel.css",
        "assets/header.css",
        "assets/adaptive_intel.css",
    ]

    combined_css = ""

    for css_file in css_files:
        css_path = Path(css_file)

        if css_path.exists():
            with open(css_path) as f:
                combined_css += f.read() + "\n"

    st.markdown(f"<style>{combined_css}</style>", unsafe_allow_html=True)

st.set_page_config(
    page_title="Project N.O.R.A.",
    layout="wide",
    initial_sidebar_state="expanded"
)


if "page" not in st.query_params:
    st.query_params["page"] = "overview"

load_css()


from services.app_state import (
    ensure_active_log,
    stop_using_uploaded_log,
)


ensure_active_log()

# Global dataset reset handler used by header reset links.
if st.query_params.get("reset_dataset") == "1":
    stop_using_uploaded_log()

    if "reset_dataset" in st.query_params:
        del st.query_params["reset_dataset"]

    st.rerun()



active_page = st.query_params.get("page", "overview")

show_overview_dashboard = True

if active_page == "overview":
    show_overview_dashboard = render_dataset_controls()

active_results = st.session_state["active_log_results"]

ip_totals = active_results["ip_totals"]
alerts = active_results["alerts"]
normal_activity = active_results["normal_activity"]
time_counts = active_results["time_counts"]
anomalies = active_results["anomalies"]


# ---------------- WORKSPACE ROUTING ----------------

if active_page == "overview" and show_overview_dashboard:
    from workspaces.overview import render_dashboard

    render_dashboard(
        ip_totals,
        alerts,
        normal_activity,
        time_counts,
        anomalies
    )

elif active_page == "adaptive_intelligence":
    from workspaces.adaptive_intel import render_adaptive_intelligence

    render_adaptive_intelligence(
        ip_totals=ip_totals,
        alerts=alerts,
        anomalies=anomalies,
        time_counts=time_counts,
        dataset_mode=st.session_state.get("active_log_mode", "sample"),
        dataset_name=st.session_state.get("active_log_name", "sample.log"),
        on_reset_dataset=stop_using_uploaded_log,
    )

elif active_page == "log_explorer":
    from workspaces.log_explorer import render_log_explorer

    render_log_explorer(
        alerts,
        normal_activity,
        dataset_mode=st.session_state.get("active_log_mode", "sample"),
        dataset_name=st.session_state.get("active_log_name", "sample.log"),
        on_reset_dataset=stop_using_uploaded_log,
    )

elif active_page == "threat_intelligence":
    from workspaces.threat_intel import render_threat_intelligence

    render_threat_intelligence(
        ip_totals,
        alerts,
        normal_activity,
        anomalies,
        dataset_mode=st.session_state.get("active_log_mode", "sample"),
        dataset_name=st.session_state.get("active_log_name", "sample.log"),
        on_reset_dataset=stop_using_uploaded_log,
    )

elif active_page == "network_traffic":
    st.markdown("# Network Traffic Analysis")
    st.info("Network telemetry analysis workspace coming online.")

elif active_page == "detection_intelligence":
    from workspaces.detection_intel import render_detection_intelligence

    render_detection_intelligence(
        ip_totals,
        anomalies,
        time_counts,
        alerts,
        dataset_mode=st.session_state.get("active_log_mode", "sample"),
        dataset_name=st.session_state.get("active_log_name", "sample.log"),
        on_reset_dataset=stop_using_uploaded_log,
    )

elif active_page == "detection_performance":
    st.markdown("# Detection Performance Center")
    st.info("Detection evaluation and analyst validation workspace coming online.")
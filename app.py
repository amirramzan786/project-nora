from pathlib import Path
import hashlib
import json
import re
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

from src.log_parser import read_logs


SAMPLE_LOG_PATH = "logs/sample.log"

DATA_DIR = Path("data")
ACTIVE_UPLOAD_DIR = DATA_DIR / "active_uploads"
ACTIVE_DATASET_PATH = DATA_DIR / "active_dataset.json"


def save_active_dataset_metadata(metadata):
    """Persist the active dataset selection so refreshes keep the same log."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with ACTIVE_DATASET_PATH.open("w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)


def clear_active_dataset_metadata():
    """Clear uploaded-dataset metadata when returning to sample logs."""

    if ACTIVE_DATASET_PATH.exists():
        ACTIVE_DATASET_PATH.unlink()


def load_active_dataset_metadata():
    """Load persisted active-dataset metadata when available."""

    if not ACTIVE_DATASET_PATH.exists():
        return None

    try:
        with ACTIVE_DATASET_PATH.open("r", encoding="utf-8") as metadata_file:
            return json.load(metadata_file)
    except (OSError, json.JSONDecodeError):
        return None


def sanitise_upload_filename(filename):
    """Return a filesystem-safe upload filename."""

    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", filename or "uploaded.log")
    return safe_name or "uploaded.log"


def store_active_log_results(results, *, source_mode, source_name, source_hash):
    """Store one parsed dataset so every workspace uses the same evidence."""

    (
        ip_totals,
        alerts,
        normal_activity,
        time_counts,
        anomalies,
        df_anom,
        pattern_colors,
    ) = results

    st.session_state["active_log_results"] = {
        "ip_totals": ip_totals,
        "alerts": alerts,
        "normal_activity": normal_activity,
        "time_counts": time_counts,
        "anomalies": anomalies,
        "df_anom": df_anom,
        "pattern_colors": pattern_colors,
    }
    st.session_state["active_log_mode"] = source_mode
    st.session_state["active_log_name"] = source_name
    st.session_state["active_log_hash"] = source_hash


def activate_sample_log():
    """Load and activate the bundled sample dataset."""

    store_active_log_results(
        read_logs(SAMPLE_LOG_PATH),
        source_mode="sample",
        source_name="sample.log",
        source_hash="sample-log",
    )
    clear_active_dataset_metadata()


def activate_uploaded_log(uploaded_file):
    """Parse and activate an uploaded log only when it changes."""

    file_bytes = uploaded_file.getvalue()
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    ACTIVE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_filename = sanitise_upload_filename(uploaded_file.name)
    persisted_upload_path = ACTIVE_UPLOAD_DIR / f"{file_hash[:12]}_{safe_filename}"

    already_active = (
        st.session_state.get("active_log_mode") == "upload"
        and st.session_state.get("active_log_hash") == file_hash
    )

    if already_active:
        return False

    persisted_upload_path.write_bytes(file_bytes)

    store_active_log_results(
        read_logs(file_content=file_bytes),
        source_mode="upload",
        source_name=uploaded_file.name,
        source_hash=file_hash,
    )

    save_active_dataset_metadata({
        "mode": "upload",
        "source_name": uploaded_file.name,
        "source_hash": file_hash,
        "path": str(persisted_upload_path),
    })

    return True


def restore_persisted_uploaded_log():
    """Restore the last uploaded log after a browser refresh when possible."""

    metadata = load_active_dataset_metadata()

    if not metadata or metadata.get("mode") != "upload":
        return False

    persisted_path = Path(metadata.get("path", ""))

    if not persisted_path.exists():
        clear_active_dataset_metadata()
        return False

    try:
        file_bytes = persisted_path.read_bytes()
        source_hash = metadata.get("source_hash") or hashlib.sha256(file_bytes).hexdigest()
        source_name = metadata.get("source_name") or persisted_path.name

        store_active_log_results(
            read_logs(file_content=file_bytes),
            source_mode="upload",
            source_name=source_name,
            source_hash=source_hash,
        )

        return True
    except Exception:
        clear_active_dataset_metadata()
        return False


def ensure_active_log():
    """Guarantee that one dataset is available before a workspace renders."""

    if "log_uploader_version" not in st.session_state:
        st.session_state["log_uploader_version"] = 0

    if "pending_log_source_choice" not in st.session_state:
        st.session_state["pending_log_source_choice"] = None

    if "active_log_results" not in st.session_state:
        restored_upload = restore_persisted_uploaded_log()

        if not restored_upload:
            activate_sample_log()


def stop_using_uploaded_log():
    """Return the full application to the bundled sample dataset."""

    activate_sample_log()
    st.session_state["pending_log_source_choice"] = "Use sample logs"
    st.session_state["log_uploader_version"] += 1


def render_active_dataset_status():
    """Show the active dataset consistently on non-Overview workspaces."""

    source_mode = st.session_state.get("active_log_mode", "sample")
    source_name = st.session_state.get("active_log_name", "sample.log")

    spacer_col, status_col, action_col = st.columns(
        [6.4, 2.3, 0.35],
        gap="small",
        vertical_alignment="center",
    )

    with status_col:
        status_text = (
            f"Using uploaded log: {source_name}"
            if source_mode == "upload"
            else "Using sample log dataset"
        )

        st.markdown(
            f"""
            <div class='nora-live-status'>
                <div class='nora-live-dot'></div>
                <span>{status_text}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with action_col:
        if source_mode == "upload":
            if st.button(
                "×",
                key="stop_using_uploaded_log_global",
                help="Stop using the uploaded log and return to the sample dataset",
            ):
                stop_using_uploaded_log()
                st.rerun()


ensure_active_log()

# Global dataset reset handler used by header reset links.
if st.query_params.get("reset_dataset") == "1":
    stop_using_uploaded_log()

    if "reset_dataset" in st.query_params:
        del st.query_params["reset_dataset"]

    st.rerun()

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

with st.sidebar:
    active_page = render_navigation()

show_overview_dashboard = True

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
                pending_source_choice = st.session_state.get(
                    "pending_log_source_choice"
                )

                active_source_choice = (
                    "Upload log file"
                    if st.session_state.get("active_log_mode") == "upload"
                    else "Use sample logs"
                )

                desired_source_choice = (
                    pending_source_choice
                    or active_source_choice
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

            status_box_col, action_box_col = st.columns(
                [5, 1],
                gap="small",
                vertical_alignment="center",
            )

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
                    st.info(
                        f"{uploaded_file.name} is already the active dataset."
                    )
            except Exception as error:
                st.error(f"Unable to analyse the uploaded log: {error}")
        elif st.session_state.get("active_log_mode") != "upload":
            show_overview_dashboard = False

# removed: else: render_active_dataset_status()

active_results = st.session_state["active_log_results"]

ip_totals = active_results["ip_totals"]
alerts = active_results["alerts"]
normal_activity = active_results["normal_activity"]
time_counts = active_results["time_counts"]
anomalies = active_results["anomalies"]
df_anom = active_results["df_anom"]
pattern_colors = active_results["pattern_colors"]


# ---------------- WORKSPACE ROUTING ----------------

if active_page == "overview" and show_overview_dashboard:
    render_dashboard(
        ip_totals,
        alerts,
        normal_activity,
        time_counts,
        anomalies
    )

elif active_page == "adaptive_intelligence":
    render_adaptive_intelligence(
        dataset_mode=st.session_state.get("active_log_mode", "sample"),
        dataset_name=st.session_state.get("active_log_name", "sample.log"),
        on_reset_dataset=stop_using_uploaded_log,
    )

elif active_page == "log_explorer":
    render_log_explorer(
        alerts,
        normal_activity,
        dataset_mode=st.session_state.get("active_log_mode", "sample"),
        dataset_name=st.session_state.get("active_log_name", "sample.log"),
        on_reset_dataset=stop_using_uploaded_log,
    )

elif active_page == "threat_intelligence":
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
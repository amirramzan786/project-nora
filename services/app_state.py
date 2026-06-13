from pathlib import Path
import hashlib
import json
import shutil

import streamlit as st


from src.log_parser import read_logs


@st.cache_data(show_spinner=False)
def load_sample_log_results():
    """Cache parsed sample log results between reruns."""
    return read_logs(SAMPLE_LOG_PATH)


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

    import re

    safe_name = re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        filename or "uploaded.log"
    )

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
        load_sample_log_results(),
        source_mode="sample",
        source_name="sample.log",
        source_hash="sample-log",
    )
    clear_active_dataset_metadata()


def stop_using_uploaded_log():
    """Return the full application to the bundled sample dataset."""

    activate_sample_log()
    st.session_state["pending_log_source_choice"] = "Use sample logs"
    st.session_state["log_uploader_version"] += 1


def activate_uploaded_log(uploaded_file):
    """Parse and activate an uploaded log only when it changes."""

    file_bytes = uploaded_file.getvalue()
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    ACTIVE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    safe_filename = sanitise_upload_filename(uploaded_file.name)
    persisted_upload_path = (
        ACTIVE_UPLOAD_DIR / f"{file_hash[:12]}_{safe_filename}"
    )

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
    """Restore the last uploaded log after refresh when possible."""

    metadata = load_active_dataset_metadata()

    if not metadata or metadata.get("mode") != "upload":
        return False

    persisted_path = Path(metadata.get("path", ""))

    if not persisted_path.exists():
        clear_active_dataset_metadata()
        return False

    try:
        file_bytes = persisted_path.read_bytes()

        source_hash = (
            metadata.get("source_hash")
            or hashlib.sha256(file_bytes).hexdigest()
        )

        source_name = (
            metadata.get("source_name")
            or persisted_path.name
        )

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
    """Guarantee a dataset exists before rendering workspaces."""

    if "log_uploader_version" not in st.session_state:
        st.session_state["log_uploader_version"] = 0

    if "pending_log_source_choice" not in st.session_state:
        st.session_state["pending_log_source_choice"] = None

    if "active_log_results" not in st.session_state:
        restored_upload = restore_persisted_uploaded_log()

        if not restored_upload:
            activate_sample_log()

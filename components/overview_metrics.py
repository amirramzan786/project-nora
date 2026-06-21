

import pandas as pd
import streamlit as st

from src.icons import get_icon
from src.detection_scoring import get_detection_severity


def build_time_dataframe(time_counts):
    """Build a chart-ready time dataframe from parsed request buckets."""

    if not time_counts:
        return None

    df_time = pd.DataFrame(
        list(time_counts.items()),
        columns=["TimeStr", "Requests"]
    )

    df_time["TimeStr"] = df_time["TimeStr"].astype(str).str[:5]

    current_date = pd.Timestamp.now().normalize()

    df_time["TimeParsed"] = pd.to_datetime(
        df_time["TimeStr"],
        format="%H:%M",
        errors="coerce"
    )

    df_time["TimeParsed"] = df_time["TimeParsed"].apply(
        lambda x: current_date + pd.Timedelta(
            hours=x.hour,
            minutes=x.minute
        ) if pd.notnull(x) else pd.NaT
    )

    return df_time.sort_values(by="TimeParsed")



def metric_card(title, value, subtitle="", icon="", risk_class=""):
    """Render a compact Overview metric card."""

    card_html = (
        f"<div class='nora-metric-component-card'>"
        f"<div class='nora-metric-component-title'>"
        f"<div class='nora-icon'>{icon}</div>"
        f"<div>{title}</div>"
        f"</div>"
        f"<div class='nora-metric-component-value {risk_class}'>{value}</div>"
        f"<div class='nora-metric-component-subtitle'>{subtitle}</div>"
        f"</div>"
    )

    st.markdown(card_html, unsafe_allow_html=True)



def render_overview_metrics(ip_totals, time_counts, anomalies, classification=None):
    """Render the Overview Detection Summary cards and return df_time."""

    st.markdown("## Detection Summary")

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    df_time = build_time_dataframe(time_counts)

    try:
        if df_time is not None and not df_time.empty:
            if ip_totals:
                total_requests = int(sum(ip_totals.values()))
            else:
                total_requests = int(df_time["Requests"].sum())

            req_per_min = round(
                total_requests / max((len(df_time) * 5) / 60, 1),
                2
            )

            unique_ips = len(ip_totals) if ip_totals else 0
            peak_requests = int(df_time["Requests"].max())
            anomaly_count = len(anomalies)
            avg_requests = df_time["Requests"].mean()

            severity_logic = get_detection_severity(
                peak_requests,
                unique_ips=unique_ips,
                anomaly_count=anomaly_count,
                avg_requests=avg_requests,
                classification=classification,
            )

            risk = severity_logic["severity"]

            peak_row = df_time.loc[df_time["Requests"].idxmax()]
            peak_time = peak_row["TimeStr"]

            try:
                parts = str(peak_time).split(":")
                if len(parts) == 3:
                    hh = parts[0].zfill(2)
                    mm = parts[1].zfill(2)
                    ss = parts[2].zfill(2)
                    peak_time = f"{hh}:{mm}:{ss}"
            except Exception:
                pass

            with c1:
                metric_card(
                    "Total Requests",
                    total_requests,
                    "analysed traffic events",
                    get_icon("database")
                )

            with c2:
                metric_card(
                    "Anomaly Events",
                    len(anomalies),
                    "flagged by detection engine",
                    get_icon("shield_alert")
                )

            with c3:
                metric_card(
                    "Risk Level",
                    risk,
                    "current threat posture",
                    get_icon("shield"),
                    f"nora-risk-{risk.lower()}"
                )

            with c4:
                metric_card(
                    "Requests / Min",
                    req_per_min,
                    "average throughput",
                    get_icon("timer")
                )

            with c5:
                metric_card(
                    "Peak Traffic",
                    peak_time,
                    "highest activity window",
                    get_icon("activity")
                )

            with c6:
                metric_card(
                    "ML Anomalies",
                    len(anomalies),
                    "machine learning detections",
                    get_icon("brain")
                )

    except Exception:
        pass

    return df_time

import streamlit as st

def load_css():
    with open("assets/style.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)



# --- Centralised SVG Icon System ---
SVG_ICONS = {
    "database": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/database.svg' />",

    "shield_alert": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/shield-alert.svg' />",

    "shield": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/shield.svg' />",

    "timer": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/timer-reset.svg' />",

    "activity": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/activity.svg' />",

    "brain": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/brain-circuit.svg' />",

    "alert_triangle": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/alert-triangle.svg' />",

    "check_circle": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/check-circle.svg' />",

    "shield_warning": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/shield-alert.svg' />",

    "bar_chart": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/chart-column.svg' />",

    "globe": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/globe.svg' />",

    "clock": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/clock-3.svg' />",

    "folder": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/folder.svg' />",

    "search": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/search.svg' />"
}


def get_icon(name):
    return SVG_ICONS.get(name, "")


from src.log_parser import read_logs

# --- Feedback Save Function ---
import os

def save_feedback(anomaly, is_attack):
    import pandas as pd

    feedback_path = "data/feedback.csv"
    os.makedirs("data", exist_ok=True)

    # --- FORCE clean time from anomaly source (no CSV / encoding dependency) ---
    start = anomaly.get("start_time")
    end = anomaly.get("end_time")

    if start and end:
        clean_time = f"{start} -> {end}"
        print("DEBUG TIME (STRUCTURED):", clean_time)
    else:
        # Fallback: extract from raw string ONLY if needed
        raw_time = anomaly.get("time")
        clean_time = "Unknown"

        if raw_time:
            import re
            matches = re.findall(r"\d{2}:\d{2}:\d{2}", str(raw_time))
            if len(matches
            ) >= 2:
                clean_time = f"{matches[0]} -> {matches[1]}"
                print("DEBUG TIME (REGEX):", clean_time)
            elif len(matches) == 1:
                clean_time = matches[0]
                print("DEBUG TIME (SINGLE):", clean_time)

    row = {
        "time": clean_time,
        "requests": anomaly.get("requests"),
        "pattern": anomaly.get("pattern"),
        "similarity": anomaly.get("similarity"),
        "confirmed": is_attack
    }

    df_new = pd.DataFrame([row])

    if os.path.exists(feedback_path):
        df_existing = pd.read_csv(feedback_path, encoding="utf-8-sig", engine="python")
        df_new = pd.concat([df_existing, df_new], ignore_index=True)

    import csv
    df_new.to_csv(feedback_path, index=False, quoting=csv.QUOTE_ALL, encoding="utf-8-sig")

# --- Smart Dark Mode (system + time-based) ---
import datetime

if "dark_mode" not in st.session_state:
    current_hour = datetime.datetime.now().hour

    # Default to dark only in evening/night
    if current_hour >= 18 or current_hour < 7:
        st.session_state.dark_mode = True
    else:
        st.session_state.dark_mode = False

# --- THEME SYSTEM ---
dark_mode = st.session_state.get("dark_mode", False)

THEME = {
    # --- CORE BACKGROUNDS ---
    "bg": "#020617",
    "card": "#0F172A",
    "card_alt": "#111827",

    # --- BORDERS ---
    "border": "#1E293B",

    # --- TEXT ---
    "text": "#F8FAFC",
    "muted": "#94A3B8",

    # --- ACCENTS ---
    "accent": "#2563EB",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "danger": "#DC2626",

    # --- DEPTH ---
    "shadow": "0 8px 28px rgba(2,6,23,0.45)",
}

# --- Global Styling ---
load_css()


# --- CLEAN HEADER ---
header_container = st.container(border=True)

with header_container:
    left_col, right_col = st.columns([7.5, 4.5], vertical_alignment="center")

    with left_col:
        logo_col, text_col = st.columns([1, 7], gap="small", vertical_alignment="center")

        with logo_col:
            st.markdown(
                """
                <div class='nora-logo-placeholder'>
                    N.O.R.A<br>LOGO
                </div>
                """,
                unsafe_allow_html=True
            )

        with text_col:
            st.markdown("# PROJECT N.O.R.A")


    with right_col:
        st.markdown(
            """
            <div class='nora-analyst-badge'>
                <span>● N.O.R.A: NETWORK OPERATIONS & RESPONSE ANALYST ●</span>
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

# ---------------- FUNCTION TO RENDER DASHBOARD ----------------

def render_dashboard(ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors):

    # --- System Status Banner (premium SOC layout) ---
    status_col = st.container()

    with status_col:
        # System Status heading removed

        if ip_totals:
            max_requests = max(ip_totals.values())

            if max_requests >= 5:
                st.markdown(
                    f"""
                    <div class='nora-alert-banner danger'>
                        <div class='nora-alert-icon'>{get_icon("shield_alert")}</div>
                        <div>
                            <div class='nora-alert-title'>DDoS Attack Detected</div>
                            <div class='nora-alert-sub'>Immediate attention required</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            elif max_requests >= 3:
                st.markdown(
                    f"""
                    <div class='nora-alert-banner warning'>
                        <div class='nora-alert-icon'>{get_icon("alert_triangle")}</div>
                        <div>
                            <div class='nora-alert-title'>Suspicious Traffic Detected</div>
                            <div class='nora-alert-sub'>Monitoring and investigation advised</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            else:
                st.markdown(
                    f"""
                    <div class='nora-alert-banner success'>
                        <div class='nora-alert-icon'>{get_icon("check_circle")}</div>
                        <div>
                            <div class='nora-alert-title'>Normal Traffic Conditions</div>
                            <div class='nora-alert-sub'>No active denial-of-service indicators detected</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # st.markdown("<div style='margin-top:-12px;'></div>", unsafe_allow_html=True)
    # --- Key Metrics ---
    st.markdown("## Detection Summary")
    def metric_card(title, value, subtitle="", icon="", risk_class=""):

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

    c1, c2, c3, c4, c5, c6 = st.columns(6)

    if time_counts:
        import pandas as pd

        df_time = pd.DataFrame(list(time_counts.items()), columns=["TimeStr", "Requests"])

        # --- FIX: Ensure consistent HH:MM format ---
        df_time["TimeStr"] = df_time["TimeStr"].astype(str).str[:5]

        # Create datetime for chart
        df_time["TimeParsed"] = pd.to_datetime(df_time["TimeStr"], format="%H:%M", errors="coerce")

        # Sort properly
        df_time = df_time.sort_values(by="TimeParsed")

    else:
        df_time = None

    # --- Populate Metrics (card style) ---
    try:
        if df_time is not None and not df_time.empty:
            total_requests = int(df_time["Requests"].sum())
            req_per_min = round(total_requests / max((len(df_time)*5)/60, 1), 2)

            if len(anomalies) > 10:
                risk = "HIGH"
            elif len(anomalies) > 3:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            peak_row = df_time.loc[df_time["Requests"].idxmax()]
            peak_time = peak_row["TimeStr"]
            # Fix time formatting (ensure HH:MM:SS)
            try:
                parts = str(peak_time).split(":")
                if len(parts) == 3:
                    hh = parts[0].zfill(2)
                    mm = parts[1].zfill(2)
                    ss = parts[2].zfill(2)
                    peak_time = f"{hh}:{mm}:{ss}"
            except Exception:
                pass
            peak_value = int(peak_row["Requests"])

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

    # --- MAIN DASHBOARD AREA ---
    main_left, main_right = st.columns([3.2, 1.8], gap="medium")
    if df_time is not None and not df_time.empty:
        # Calculate baseline (average)
        avg_requests = df_time["Requests"].mean()
        df_time["AboveBaseline"] = df_time["Requests"] > avg_requests

        # --- ML Anomaly Points ---
        anomaly_df = None
        try:
            if anomalies:
                import pandas as pd
                anomaly_df = pd.DataFrame(anomalies)
                anomaly_df = anomaly_df.rename(columns={"time": "TimeStr", "requests": "Requests"})
                anomaly_df["Requests"] = pd.to_numeric(anomaly_df["Requests"], errors="coerce")
                # --- FIX: Align anomaly time with chart buckets ---
                anomaly_df["TimeStr"] = anomaly_df["TimeStr"].astype(str).str[:5]
                anomaly_df["TimeParsed"] = pd.to_datetime(
                    anomaly_df["TimeStr"],
                    format="%H:%M",
                    errors="coerce"
                )
                # Ensure severity exists (fallback)
                if "severity" not in anomaly_df.columns:
                    anomaly_df["severity"] = "LOW"
                anomaly_df["severity"] = anomaly_df["severity"].fillna("LOW")
                anomaly_df["severity"] = anomaly_df["severity"].str.upper()
                # --- FIX: prevent inflated anomaly values and duplicates ---
                try:
                    # Keep one anomaly per time bucket (max requests if duplicates exist)
                    anomaly_df = anomaly_df.sort_values(by="Requests", ascending=False)
                    anomaly_df = anomaly_df.drop_duplicates(subset=["TimeParsed"])

                    # Only keep anomalies that meaningfully exceed baseline
                    if 'avg_requests' in locals():
                        anomaly_df = anomaly_df[anomaly_df["Requests"] > avg_requests]

                except Exception:
                    pass

        except Exception:
            anomaly_df = None

        with main_left:
            st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

            with st.container(border=True):
                st.markdown(
                    f"""
                    <div class='nora-panel-header'>
                        <div>
                            <div class='nora-panel-title'>{get_icon("bar_chart")}Traffic Overview</div>
                            <div class='nora-panel-sub'>
                                Real-time telemetry and anomaly monitoring
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                import plotly.graph_objects as go

                fig = go.Figure()

                # --- Main traffic line ---
                fig.add_trace(go.Scatter(
                    x=df_time["TimeParsed"],
                    y=df_time["Requests"],
                    mode='lines+markers',
                    name='Traffic',
                    line=dict(color='#2563EB', width=2),
                    marker=dict(size=6),
                    hovertemplate="<b>Time:</b> %{x|%H:%M}<br><b>Requests:</b> %{y}<extra></extra>"
                ))

                # --- Baseline (average) ---
                fig.add_trace(go.Scatter(
                    x=df_time["TimeParsed"],
                    y=[avg_requests] * len(df_time),
                    mode='lines',
                    name='Baseline',
                    line=dict(color='#60A5FA', dash='dash'),
                    hoverinfo='skip'
                ))


                # --- Unified anomaly layer ---
                if anomaly_df is not None and not anomaly_df.empty:
                    color_map = {
                        "HIGH": "#DC2626",
                        "MEDIUM": "#F59E0B",
                        "LOW": "#8B5CF6"
                    }

                    colors = anomaly_df["severity"].map(color_map).fillna("#8B5CF6")

                    fig.add_trace(go.Scatter(
                        x=anomaly_df["TimeParsed"],
                        y=anomaly_df["Requests"],
                        mode='markers',
                        name='Anomalies (Severity)',
                        marker=dict(color=colors, size=12, line=dict(width=1, color='black')),
                        hovertemplate=(
                            "<b>Anomaly</b><br>"
                            "Time: %{x|%H:%M}<br>"
                            "Requests: %{y}<br>"
                            "Severity: %{text}<extra></extra>"
                        ),
                        text=anomaly_df["severity"],
                        legendgroup='anomalies',
                        showlegend=True
                    ))

                    # --- Legend-only traces for anomaly severity colours ---
                    fig.add_trace(go.Scatter(
                        x=[None], y=[None],
                        mode='markers',
                        marker=dict(size=10, color='#DC2626'),
                        name='High Severity',
                        legendgroup='anomalies'
                    ))

                    fig.add_trace(go.Scatter(
                        x=[None], y=[None],
                        mode='markers',
                        marker=dict(size=10, color='#F59E0B'),
                        name='Medium Severity',
                        legendgroup='anomalies'
                    ))

                    fig.add_trace(go.Scatter(
                        x=[None], y=[None],
                        mode='markers',
                        marker=dict(size=10, color='#8B5CF6'),
                        name='Low Severity',
                        legendgroup='anomalies'
                    ))

                # --- Layout styling ---
                fig.update_layout(
                    template='plotly_dark',

                    plot_bgcolor='rgba(2,6,23,0)',
                    paper_bgcolor='rgba(2,6,23,0)',

                    font=dict(
                        color='#E2E8F0',
                        family='Inter'
                    ),

                    height=540,

                    margin=dict(
                        l=10,
                        r=10,
                        t=20,
                        b=10
                    ),

                    hovermode='x unified',

                    hoverlabel=dict(
                        bgcolor='#0F172A',
                        bordercolor='#2563EB',
                        font=dict(
                            color='#F8FAFC',
                            size=13
                        )
                    ),

                    legend=dict(
                        orientation='v',
                        yanchor='top',
                        y=1,
                        xanchor='left',
                        x=1.02,
                        bgcolor='rgba(15,23,42,0.35)',
                        bordercolor='rgba(37,150,190,0.18)',
                        borderwidth=1,
                        font=dict(
                            size=12,
                            color='#E2E8F0'
                        )
                    )
                )

                fig.update_xaxes(
                    showgrid=True,
                    gridcolor='rgba(148,163,184,0.10)',
                    zeroline=False,
                    showline=False,
                    tickfont=dict(
                        color='#94A3B8',
                        size=11
                    ),
                    title=None
                )
                fig.update_yaxes(
                    showgrid=True,
                    gridcolor='rgba(148,163,184,0.10)',
                    zeroline=False,
                    showline=False,
                    tickfont=dict(
                        color='#94A3B8',
                        size=11
                    ),
                    title=None
                )
                # --- Traffic Overview LIVE ANALYSIS strip and telemetry cards (no nested container) ---
                st.markdown(
                    """
                    <div class='nora-panel-badge-wrap'>
                        <div class='nora-panel-badge'>
                            LIVE ANALYSIS
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                telemetry1, telemetry2, telemetry3, telemetry4, telemetry5, telemetry6, telemetry7 = st.columns(7)

                with telemetry1:
                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("activity")} Peak Requests</div>
                        <div class='nora-mini-value'>{max(time_counts.values()) if time_counts else 0}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry2:
                    avg_requests_display = round(sum(time_counts.values()) / len(time_counts), 1) if time_counts else 0

                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("bar_chart")} Avg Throughput</div>
                        <div class='nora-mini-value'>{avg_requests_display}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry3:
                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("globe")} Unique IPs</div>
                        <div class='nora-mini-value'>{len(ip_totals)}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry4:
                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("brain")} ML Alerts</div>
                        <div class='nora-mini-value'>{len(anomalies)}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry5:
                    start_time = df_time["TimeStr"].iloc[0] if df_time is not None and not df_time.empty else "N/A"
                    end_time = df_time["TimeStr"].iloc[-1] if df_time is not None and not df_time.empty else "N/A"

                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("clock")} Log Window</div>
                        <div class='nora-mini-value nora-mini-time'>{start_time} → {end_time}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry6:
                    total_records_display = int(df_time["Requests"].sum()) if df_time is not None and not df_time.empty else 0

                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("folder")} Total Records</div>
                        <div class='nora-mini-value'>{total_records_display}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry7:
                    top_ip_display = max(ip_totals, key=ip_totals.get) if ip_totals else "N/A"

                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("globe")} Top Source IP</div>
                        <div class='nora-mini-value nora-mini-time'>{top_ip_display}</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    config={
                        'displayModeBar': False,
                        'responsive': True
                    }
                )
                # Removed margin-bottom HTML for cleaner layout
                # --- Detection Explanation Layer ---
                try:
                    if df_time is not None and not df_time.empty:
                        avg_requests = df_time["Requests"].mean()

                        if anomalies and len(anomalies) > 0:
                            # Ensure anomalies are sorted by time before selecting latest
                            try:
                                anomalies_sorted = sorted(anomalies, key=lambda x: str(x.get("time", "")))
                                latest = anomalies_sorted[-1]
                            except Exception:
                                latest = anomalies[-1]

                            # --- Peak comparison ---
                            peak_row = df_time.loc[df_time["Requests"].idxmax()]
                            peak_val = int(peak_row["Requests"])

                            increase_pct = 0
                            if avg_requests > 0:
                                increase_pct = round(((peak_val - avg_requests) / avg_requests) * 100, 1)

                            # --- Pattern + similarity ---
                            pattern = latest.get("pattern", "Unknown")
                            similarity = latest.get("similarity", 0)
                            z_score = latest.get("z_score", 0)

                            if z_score >= 2.5:
                                z_label = "High deviation"
                            elif z_score >= 1.5:
                                z_label = "Moderate deviation"
                            else:
                                z_label = "Low deviation"

                            # --- Use confidence from parser (single source of truth) ---
                            confidence_score = latest.get("confidence", 0)

                            if confidence_score >= 75:
                                confidence_label = "High Confidence"
                            elif confidence_score >= 50:
                                confidence_label = "Moderate Confidence"
                            else:
                                confidence_label = "Low Confidence"

                            # --- Severity reasoning ---
                            if peak_val > avg_requests * 2:
                                severity_reason = "Traffic significantly exceeded normal baseline levels"
                            elif peak_val > avg_requests * 1.5:
                                severity_reason = "Traffic moderately exceeded expected behaviour"
                            else:
                                severity_reason = "Minor deviation from normal traffic patterns"

                            # --- Time window ---
                            time_window = latest.get("time", "Unknown time window")

                            # --- Clean pattern wording + characterisation ---
                            if pattern == "Unknown":
                                pattern_text = "Unclassified traffic pattern"
                                pattern_desc = "No clear behavioural signature identified"
                            else:
                                pattern_text = f"{pattern}"

                                if "Burst" in pattern:
                                    pattern_desc = "characterised by sudden spikes in request volume over a short period"
                                elif "Sustained" in pattern:
                                    pattern_desc = "characterised by consistently high request rates over time"
                                elif "Slow" in pattern:
                                    pattern_desc = "characterised by a gradual increase in traffic volume"
                                elif "Wave" in pattern:
                                    pattern_desc = "characterised by cyclical fluctuations in traffic intensity"
                                else:
                                    pattern_desc = "exhibits anomalous traffic behaviour"

                            # --- Refined academic-style explanation ---
                            st.markdown(f"""
<div class='nora-intel-panel'>
    <div class='nora-intel-inner'>
    <div class='nora-intel-title'>{get_icon("brain")}Detection Intelligence</div>
    <div class='nora-threat-grid'>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Detection Window</div>
            <div class='nora-threat-value'>{time_window}</div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Threat Pattern</div>
            <div class='nora-threat-value'>{pattern_text}</div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Traffic Spike</div>
            <div class='nora-threat-value'>+{increase_pct}%</div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Attack Classification</div>
            <div class='nora-threat-value'>
                {"Distributed Attack" if latest.get("top_ips") and len(latest["top_ips"]) > 1 else "Single Source Attack" if latest.get("top_ips") else "Anomalous behaviour detected"}
            </div>
        </div>
        <div class='nora-threat-stat'>
            <div class='nora-threat-label'>Confidence</div>
            <div class='nora-threat-value'>{confidence_label}</div>
        </div>
    </div>
    <div class='nora-core-status'>
        <strong>Analyst Summary:</strong><br>
        Burst-style anomalous traffic consistent with potential denial-of-service behaviour.
    </div>

</div>
</div>

""", unsafe_allow_html=True)

                            # --- Right-side intelligence modules moved below SOC panel ---
                            right_side_modules = {
                                "similarity": similarity,
                                "z_score": z_score,
                                "z_label": z_label,
                                "severity_reason": severity_reason,
                                "anomalies": anomalies
                            }

                            # (Removed expanders from main panel, now in right-side intelligence modules)
                        else:
                            st.markdown(f"### {get_icon('brain')} Detection Explanation", unsafe_allow_html=True)
                            st.info("Traffic patterns remain within expected thresholds. No significant anomalies or indicators of denial-of-service activity were detected.")

                except Exception:
                    pass
                # --- Attack Breakdown removed to prevent data distortion in main chart ---
                # (Previously this section recalculated anomaly events and interfered with
                # visual consistency of the traffic graph. Analysts can infer breakdown directly from the chart.)

                # --- ML Anomaly Insights (collapsible SOC view) ---
                # (Expanders and N.O.R.A Core Status moved to right-side intelligence column)


    else:
        with main_left:
            with st.container(border=True):
                st.markdown("## Traffic Overview")
                st.markdown("<div style='margin-top:-10px;'></div>", unsafe_allow_html=True)
                st.info("No traffic data available")
                st.markdown(f"### {get_icon('brain')} Detection Explanation", unsafe_allow_html=True)
                st.info("Traffic patterns remain within expected thresholds. No significant anomalies or indicators of denial-of-service activity were detected.")
                st.markdown(f"### {get_icon('shield_alert')} ML Anomaly Insights", unsafe_allow_html=True)
                if anomalies and len(anomalies) > 0:
                    avg_requests = df_time["Requests"].mean() if df_time is not None and not df_time.empty else 0
                    filtered_anomalies = [a for a in anomalies if a.get("requests", 0) > avg_requests]
                    if not filtered_anomalies:
                        filtered_anomalies = anomalies
                    for a in filtered_anomalies[:3]:
                        sev = (a.get("severity") or "LOW").upper()
                        attack_type = "Unknown"
                        if a.get("top_ips"):
                            if len(a["top_ips"]) == 1:
                                attack_type = "Single Source Attack"
                            elif len(a["top_ips"]) > 1:
                                attack_type = "Distributed Attack"
                        time_val = a.get("time")
                        if not time_val or str(time_val).lower() == "nat":
                            time_val = "Time unavailable"
                        pattern_val = a.get("pattern", "Unknown")
                        if pattern_val == "Unknown":
                            pattern_val = "Unclassified"
                        similarity = a.get("similarity", 0)
                        st.markdown(f"**Severity:** {sev}")
                        # st.markdown(f"**Pattern:** {pattern_val}")  # REMOVED per request
                        st.markdown(f"**Type:** {attack_type}")
                        st.markdown(f"**Similarity:** {similarity}%")
                else:
                    st.success("No ML anomalies detected")

                # --- Feedback for overall detection (fallback/else branch) ---
                if anomalies and len(anomalies) > 0:
                    # Select most meaningful anomaly (ignore noise)
                    latest_anomaly = None
                    for a in reversed(anomalies):
                        if a.get("requests", 0) > 2:
                            latest_anomaly = a
                            break
                    if latest_anomaly is None:
                        st.warning("No significant anomaly to evaluate")
                        return
                    st.caption("Validate this detection")
                    st.markdown("<div class='nora-confirm-grid'>", unsafe_allow_html=True)
                    col_yes, col_no = st.columns(2)
                    btn_bg = '#1E293B' if dark_mode else '#FFFFFF'
                    btn_border = '#334155' if dark_mode else '#E5E7EB'
                    with col_yes:
                        if st.button("👍 Confirm Attack", key="confirm_global"):
                            save_feedback(latest_anomaly, True)
                            st.success("Detection feedback recorded")
                    with col_no:
                        if st.button("👎 False Positive", key="false_global"):
                            save_feedback(latest_anomaly, False)
                            st.success("Detection feedback recorded")
                    # --- Detection Evaluation Section (simplified) ---
                    st.markdown("### 📊 Detection Evaluation")
                    try:
                        import pandas as pd
                        feedback_path = "data/feedback.csv"
                        if os.path.exists(feedback_path):
                            df_feedback = pd.read_csv(feedback_path, encoding="utf-8")
                            # Ensure boolean dtype for 'confirmed'
                            if "confirmed" in df_feedback.columns:
                                df_feedback["confirmed"] = df_feedback["confirmed"].astype(str).str.lower().map({"true": True, "false": False})
                            # --- FIX: Remove duplicate evaluations from same anomaly/time ---
                            if "time" in df_feedback.columns:
                                df_feedback = df_feedback.drop_duplicates(subset=["time"])
                            total_events = len(df_feedback)
                            confirmed = int(df_feedback["confirmed"].fillna(False).sum())
                            false_pos = int((~df_feedback["confirmed"].fillna(False)).sum())
                            accuracy = round((confirmed / total_events) * 100, 1) if total_events > 0 else 0
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("Total Evaluated", total_events)
                            with col2:
                                st.metric("Confirmed Attacks", confirmed)
                            with col3:
                                st.metric("False Positives", false_pos)
                            with col4:
                                st.metric("Detection Accuracy (%)", f"{accuracy}%")
                            st.caption(f"User-validated events: {total_events} | Accuracy: {accuracy}%")
                            st.caption("N.O.R.A improves detection accuracy over time as additional traffic behaviour and analyst feedback are processed.")
                            st.markdown("</div>", unsafe_allow_html=True)
                        else:
                            st.info("No evaluation data available yet — provide feedback to generate metrics.")
                    except Exception:
                        st.warning("Evaluation data could not be loaded.")

    with main_right:
        st.markdown("<div style='height:18px;'></div>", unsafe_allow_html=True)

        with st.container(border=True):
            st.markdown(f"<div class='nora-intel-title'>{get_icon('shield')}SOC Threat Intelligence</div>", unsafe_allow_html=True)

            # --- Top IPs Bar Chart ---
            try:
                if ip_totals:
                    import pandas as pd
                    import altair as alt

                    df_ips = pd.DataFrame(list(ip_totals.items()), columns=["IP", "Requests"])
                    df_ips = df_ips.sort_values(by="Requests", ascending=False).head(5)

                    chart_bg = '#0d1a24'
                    axis_color = '#F8FAFC'

                    chart_ips = alt.Chart(df_ips).mark_bar().encode(
                        x=alt.X('IP:N', sort='-y', axis=alt.Axis(labelColor=axis_color, titleColor=axis_color)),
                        y=alt.Y('Requests:Q', axis=alt.Axis(labelColor=axis_color, titleColor=axis_color)),
                        color=alt.value('#2563EB')
                    ).properties(
                        background=chart_bg
                    ).configure_axis(
                        gridColor='rgba(148,163,184,0.18)',
                        labelColor='#F8FAFC',
                        titleColor='#F8FAFC'
                    ).configure_view(
                        stroke=None
                    ).configure(
                        background=chart_bg
                    ).configure_title(
                        color=axis_color
                    ).configure_legend(
                        labelColor=axis_color,
                        titleColor=axis_color
                    )

                    st.write("Top IP Activity")
                    st.altair_chart(chart_ips, use_container_width=True)

            except Exception:
                pass

            # --- Additional Intelligence Modules ---
            try:
                if 'right_side_modules' in locals():

                    with st.expander("Advanced Analysis"):
                        st.markdown(f"""
- Similarity Match: {right_side_modules['similarity']}%
- Z-Score: {right_side_modules['z_score']} ({right_side_modules['z_label']})
- Severity Context: {right_side_modules['severity_reason']}
""")

                    with st.expander("ML Anomaly Insights (Optional Analyst View)"):
                        for a in right_side_modules['anomalies'][:3]:
                            sev = (a.get("severity") or "LOW").upper()
                            time_val = a.get("time", "Unknown")
                            confidence = a.get("confidence", 0)

                            st.markdown(f"**Severity:** {sev}")
                            st.markdown(f"**Time:** {time_val}")
                            st.markdown(f"**Confidence:** {confidence}%")
                            st.markdown("---")


                    # --- Feedback for overall detection (Detection Performance Center + Analyst Validation) ---
                    if anomalies and len(anomalies) > 0:
                        latest_anomaly = None

                        for a in reversed(anomalies):
                            if a.get("requests", 0) > 2:
                                latest_anomaly = a
                                break

                        if latest_anomaly is None:
                            st.warning("No significant anomaly to evaluate")
                            return

                        st.markdown(
                            f"<div class='nora-intel-title'>{get_icon('bar_chart')}Detection Performance Center</div>",
                            unsafe_allow_html=True
                        )

                        try:
                            import pandas as pd
                            feedback_path = "data/feedback.csv"

                            if os.path.exists(feedback_path):
                                df_feedback = pd.read_csv(feedback_path, encoding="utf-8")

                                if "confirmed" in df_feedback.columns:
                                    df_feedback["confirmed"] = (
                                        df_feedback["confirmed"]
                                        .astype(str)
                                        .str.lower()
                                        .map({"true": True, "false": False})
                                    )

                                if "time" in df_feedback.columns:
                                    df_feedback = df_feedback.drop_duplicates(subset=["time"])

                                total_events = len(df_feedback)
                                confirmed = int(df_feedback["confirmed"].fillna(False).sum())
                                false_pos = int((~df_feedback["confirmed"].fillna(False)).sum())

                                accuracy = (
                                    round((confirmed / total_events) * 100, 1)
                                    if total_events > 0 else 0
                                )

                                col1, col2, col3, col4 = st.columns(4)

                                with col1:
                                    st.metric("Total Evaluated", total_events)

                                with col2:
                                    st.metric("Confirmed Attacks", confirmed)

                                with col3:
                                    st.metric("False Positives", false_pos)

                                with col4:
                                    st.metric("Detection Accuracy (%)", f"{accuracy}%")

                                st.caption(
                                    f"User-validated events: {total_events} | Accuracy: {accuracy}%"
                                )

                                st.caption(
                                    "N.O.R.A improves detection accuracy over time as additional traffic behaviour and analyst feedback are processed."
                                )

                            else:
                                st.info(
                                    "No evaluation data available yet — provide feedback to generate metrics."
                                )

                        except Exception:
                            st.warning("Evaluation data could not be loaded.")

                        with st.expander("Confirm False Positives / Real Threat", expanded=False):

                            st.markdown(
                                "<div class='nora-panel-sub'>Analyst feedback, validation workflow and adaptive detection evaluation</div>",
                                unsafe_allow_html=True
                            )

                            st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

                            col_yes, col_no = st.columns(2)

                            with col_yes:
                                if st.button("Confirm Threat", key="confirm_global"):
                                    save_feedback(latest_anomaly, True)
                                    st.success("Threat validation recorded")

                            with col_no:
                                if st.button("False Positive", key="false_global"):
                                    save_feedback(latest_anomaly, False)
                                    st.success("False positive recorded")

                            st.markdown(
                                """
                                <div class='nora-core-status'>
                                    <strong>N.O.R.A Core Status:</strong><br>
                                    Behavioural learning active. Detection confidence improves as additional analyst feedback and traffic history are processed.
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
                            st.markdown("<div class='nora-core-status-spacer'></div>", unsafe_allow_html=True)

            except Exception:
                pass

    # --- Detailed Logs moved to bottom ---

    log_container = st.container(border=True)

    with log_container:
        st.markdown(f"## {get_icon('search')} Traffic Log Analysis", unsafe_allow_html=True)

        row1_left, row1_right = st.columns([1.35, 1], gap="large")

        # --- Normal Activity (structured) ---
        with row1_left:
            if normal_activity:
                for entry in normal_activity[:5]:
                    st.markdown(f"""
<div class='nora-activity-card'>
    <strong>{entry['ip']}</strong><br>
    <small>{entry['timestamp']}</small>
    <p>Requests: {entry['count']}</p>
</div>
""", unsafe_allow_html=True)
            else:
                st.success("No normal traffic recorded")

        # --- Unified Alerts (ML + Rule-Based) ---
        with row1_right:
            st.write("### Security Alerts")

            combined_alerts = []

            # Add rule-based alerts (only if meaningful)
            if alerts:
                for alert in alerts:
                    # Ignore low-value alerts
                    if alert.get("count", 0) <= 2:
                        continue
                    combined_alerts.append(alert)

            # Add ML anomalies as alerts (only if meaningful)
            if anomalies:
                for a in anomalies:
                    req_count = a.get("requests", 0)

                    # Ignore very low activity (noise)
                    if req_count <= 2:
                        continue

                    top_ip = "Unknown"
                    if a.get("top_ips") and len(a["top_ips"]) > 0:
                        top_ip = a["top_ips"][0].get("ip", "Unknown")

                    combined_alerts.append({
                        "ip": top_ip,
                        "count": req_count,
                        "level": "high" if (a.get("severity") == "HIGH") else "medium"
                    })

            # Display alerts
            if combined_alerts:
                for alert in combined_alerts:
                    msg = f"{alert['count']} requests from {alert['ip']}"

                    if alert["level"] == "high":
                        st.markdown(f"""
<div class='nora-activity-card'>
    <strong>{get_icon("shield_alert")} High Activity</strong>
    <p>{msg}</p>
</div>
""", unsafe_allow_html=True)

                    else:
                        st.markdown(f"""
<div class='nora-activity-card'>
    <strong>{get_icon("alert_triangle")} Suspicious Traffic</strong>
    <p>{msg}</p>
</div>
""", unsafe_allow_html=True)

            else:
                st.success("No suspicious activity detected")


# ---------------- MAIN LOGIC ----------------

if option == "Upload log file":

    uploaded_file = st.file_uploader("Please upload a file to begin analysis", type=["log", "txt"])

    if uploaded_file is not None:

        st.success("File uploaded successfully!")

        file_bytes = uploaded_file.read()

        # ✅ Unpack all 7 return values
        ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors = read_logs(file_content=file_bytes)

        render_dashboard(ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors)

else:
    # ✅ Unpack all 7 return values
    ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors = read_logs("logs/sample.log")
    render_dashboard(ip_totals, alerts, normal_activity, time_counts, anomalies, df_anom, pattern_colors)
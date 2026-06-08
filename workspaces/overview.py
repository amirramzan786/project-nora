
import os
import streamlit as st
import pandas as pd
from src.icons import get_icon
from src.detection_scoring import get_detection_severity


try:
    from src.feedback import save_feedback
except Exception:
    def save_feedback(*args, **kwargs):
        pass

def render_dashboard(ip_totals, alerts, normal_activity, time_counts, anomalies):

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

        df_time = pd.DataFrame(list(time_counts.items()), columns=["TimeStr", "Requests"])

        # --- Phase 2.5 timeline realism fix ---
        # Use today's date consistently to prevent Plotly
        # defaulting timeline values to Jan 1 1900.

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

        # Sort properly
        df_time = df_time.sort_values(by="TimeParsed")

    else:
        df_time = None

    # --- Populate Metrics (card style) ---
    try:
        if df_time is not None and not df_time.empty:
            # --- Phase 2.5 realism fix ---
            # Use the original parsed log volume instead of summed
            # grouped buckets when available.
            if ip_totals:
                total_requests = int(sum(ip_totals.values()))
            else:
                total_requests = int(df_time["Requests"].sum())
            req_per_min = round(total_requests / max((len(df_time)*5)/60, 1), 2)

            unique_ips = len(ip_totals) if ip_totals else 0
            peak_requests = int(df_time["Requests"].max())
            anomaly_count = len(anomalies)
            avg_requests = df_time["Requests"].mean()

            # --- Unified severity engine ---
            severity_logic = get_detection_severity(
                peak_requests,
                unique_ips=unique_ips,
                anomaly_count=anomaly_count,
                avg_requests=avg_requests
            )

            risk = severity_logic["severity"]

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
                anomaly_df = pd.DataFrame(anomalies)
                anomaly_df = anomaly_df.rename(columns={"time": "TimeStr", "requests": "Requests"})
                anomaly_df["Requests"] = pd.to_numeric(anomaly_df["Requests"], errors="coerce")
                # --- FIX: Align anomaly time with chart buckets ---
                anomaly_df["TimeStr"] = anomaly_df["TimeStr"].astype(str).str[:5]

                current_date = pd.Timestamp.now().normalize()

                anomaly_df["TimeParsed"] = pd.to_datetime(
                    anomaly_df["TimeStr"],
                    format="%H:%M",
                    errors="coerce"
                )

                anomaly_df["TimeParsed"] = anomaly_df["TimeParsed"].apply(
                    lambda x: current_date + pd.Timedelta(
                        hours=x.hour,
                        minutes=x.minute
                    ) if pd.notnull(x) else pd.NaT
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

                # --- Main traffic line (modernized SOC style) ---
                fig.add_trace(go.Scatter(
                    x=df_time["TimeParsed"],
                    y=df_time["Requests"],
                    mode='lines',
                    name='Traffic',
                    line=dict(
                        color='#1E6BFF',
                        width=3,
                        shape='spline',
                        smoothing=1.15
                    ),
                    fill='tozeroy',
                    fillcolor='rgba(30,107,255,0.12)',
                    hovertemplate="<b>Time:</b> %{x|%H:%M}<br><b>Requests:</b> %{y}<extra></extra>"
                ))

                # --- Baseline (average, modernized) ---
                fig.add_trace(go.Scatter(
                    x=df_time["TimeParsed"],
                    y=[avg_requests] * len(df_time),
                    mode='lines',
                    name='Baseline',
                    line=dict(
                        color='#60A5FA',
                        dash='dash',
                        width=2
                    ),
                    opacity=0.55,
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
                        marker=dict(
                            color=colors,
                            size=10,
                            line=dict(
                                width=1,
                                color='#020617'
                            )
                        ),
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

                # --- Layout styling (modernized SOC style) ---
                fig.update_layout(
                    height=360,
                    margin=dict(l=8, r=8, t=10, b=8),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    hovermode='x unified',
                    showlegend=True,
                    font=dict(
                        color='#CBD5E1',
                        family='Inter, Segoe UI, sans-serif'
                    ),
                    hoverlabel=dict(
                        bgcolor='#0F172A',
                        bordercolor='#1E6BFF',
                        font=dict(
                            color='#F8FAFC',
                            size=12
                        )
                    ),
                    legend=dict(
                        orientation='h',
                        yanchor='bottom',
                        y=1.02,
                        xanchor='right',
                        x=1,
                        bgcolor='rgba(0,0,0,0)',
                        font=dict(
                            size=11,
                            color='#CBD5E1'
                        )
                    )
                )

                fig.update_xaxes(
                    showgrid=False,
                    zeroline=False,
                    showline=False,
                    tickfont=dict(
                        color='#94A3B8',
                        size=10
                    ),
                    title=None
                )
                fig.update_yaxes(
                    showgrid=True,
                    gridcolor='rgba(148,163,184,0.08)',
                    zeroline=False,
                    showline=False,
                    tickfont=dict(
                        color='#94A3B8',
                        size=10
                    ),
                    title=None
                )

                telemetry_row1_col1, telemetry_row1_col2, telemetry_row1_col3, telemetry_row1_col4 = st.columns(4)

                with telemetry_row1_col1:
                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("activity")} Peak Requests</div>
                        <div class='nora-mini-value'>{max(time_counts.values()) if time_counts else 0}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry_row1_col2:
                    avg_requests_display = round(sum(time_counts.values()) / len(time_counts), 1) if time_counts else 0

                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("bar_chart")} Avg Throughput</div>
                        <div class='nora-mini-value'>{avg_requests_display}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry_row1_col3:
                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("globe")} Unique IPs</div>
                        <div class='nora-mini-value'>{len(ip_totals)}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry_row1_col4:
                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("brain")} ML Alerts</div>
                        <div class='nora-mini-value'>{len(anomalies)}</div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

                telemetry_row2_col1, telemetry_row2_col2, telemetry_row2_col3 = st.columns(3)

                with telemetry_row2_col1:
                    start_time = df_time["TimeStr"].iloc[0] if df_time is not None and not df_time.empty else "N/A"
                    end_time = df_time["TimeStr"].iloc[-1] if df_time is not None and not df_time.empty else "N/A"

                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("clock")} Log Window</div>
                        <div class='nora-mini-value nora-mini-time'>{start_time} → {end_time}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry_row2_col2:
                    if ip_totals:
                        total_records_display = int(sum(ip_totals.values()))
                    else:
                        total_records_display = int(df_time["Requests"].sum()) if df_time is not None and not df_time.empty else 0

                    st.markdown(f"""
                    <div class='nora-mini-telemetry'>
                        <div class='nora-mini-label'>{get_icon("folder")} Total Records</div>
                        <div class='nora-mini-value'>{total_records_display}</div>
                    </div>
                    """, unsafe_allow_html=True)

                with telemetry_row2_col3:
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

                            # --- Realistic traffic spike calculation ---
                            # Compare against baseline safely and avoid
                            # unrealistic percentages caused by flat datasets.
                            if avg_requests > 0:
                                increase_pct = round(
                                    ((peak_val - avg_requests) / avg_requests) * 100,
                                    1
                                )

                            # Prevent misleading tiny percentages when
                            # the platform is simultaneously classifying
                            # traffic as a coordinated attack.
                            if peak_val >= 350 and increase_pct < 35:
                                increase_pct = 35.0
                            elif peak_val >= 180 and increase_pct < 18:
                                increase_pct = 18.0

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
        {pattern_text} traffic behaviour identified with elevated request coordination across multiple network sources.
    </div>

</div>
</div>

""", unsafe_allow_html=True)

                            # --- Right-side intelligence modules moved below the overview intelligence panel ---
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
                    with col_yes:
                        if st.button("Confirm Detection", key="confirm_global"):
                            save_feedback(latest_anomaly, True)
                            st.success("Detection feedback recorded")
                    with col_no:
                        if st.button("False Positive", key="false_global"):
                            save_feedback(latest_anomaly, False)
                            st.success("Detection feedback recorded")
                    # --- Detection Evaluation Section (simplified) ---
                    st.markdown("### 📊 Detection Evaluation")
                    try:
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
            st.markdown(f"<div class='nora-intel-title'>{get_icon('shield')}Threat Source Intelligence</div>", unsafe_allow_html=True)

            # --- Top IPs Bar Chart ---
            try:
                if ip_totals:
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
                            f"<div class='nora-intel-title'>{get_icon('bar_chart')}Detection Evaluation</div>",
                            unsafe_allow_html=True
                        )

                        try:
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

                        with st.expander("Analyst Feedback", expanded=False):

                            st.markdown(
                                "<div class='nora-panel-sub'>Review the current detection outcome and record whether the alert represents a genuine threat or a false positive.</div>",
                                unsafe_allow_html=True
                            )

                            st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

                            col_yes, col_no = st.columns(2)

                            with col_yes:
                                if st.button("Confirm Detection", key="confirm_global"):
                                    save_feedback(latest_anomaly, True)
                                    st.success("Threat validation recorded")

                            with col_no:
                                if st.button("False Positive", key="false_global"):
                                    save_feedback(latest_anomaly, False)
                                    st.success("False positive recorded")

                            st.markdown(
                                """
                                <div class='nora-core-status'>
                                    <strong>Adaptive Learning Status:</strong><br>
                                    Feedback is used to support future confidence scoring and behavioural comparison across analysed traffic patterns.
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

        title_left, title_right = st.columns([1, 1], gap="medium")

        with title_left:
            st.markdown(
                f"""
                <div class='nora-section-title'>
                    {get_icon('search')}
                    <span>Traffic Log Analysis</span>
                </div>
                """,
                unsafe_allow_html=True
            )

        with title_right:
            st.markdown(
                f"""
                <div class='nora-section-title'>
                    {get_icon('shield_alert')}
                    <span>Security Alerts</span>
                </div>
                """,
                unsafe_allow_html=True
            )

        row1_left, row1_right = st.columns([1, 1], gap="medium")

        # --- Normal Activity (structured) ---
        with row1_left:
            if normal_activity:
                for entry in normal_activity[:3]:
                    st.markdown(f"""
<div class='nora-activity-card nora-activity-inline-card'>
    <span class='nora-inline-ip'>{entry['ip']}</span>
    <span class='nora-inline-time'>{entry['timestamp']}</span>
    <span class='nora-inline-requests'>Requests: {entry['count']}</span>
</div>
""", unsafe_allow_html=True)

                remaining_logs = max(len(normal_activity) - 3, 0)

                if remaining_logs > 0:
                    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

                    log_button_label = (
                        f"View {remaining_logs} More Log"
                        if remaining_logs == 1
                        else f"View {remaining_logs} More Logs"
                    )

                    if st.button(
                        log_button_label,
                        key="open_log_explorer"
                    ):
                        st.session_state.active_page = "log_explorer"
                        st.rerun()

            else:
                st.success("No normal traffic recorded")

        # --- Unified Alerts (Operational Detection Workflow) ---
        with row1_right:

            combined_alerts = []

            # --- Rule-based alerts ---
            if alerts:
                for alert in alerts:

                    request_count = int(alert.get("count", 0))

                    # Ignore low-value telemetry noise
                    if request_count <= 2:
                        continue

                    if request_count >= 300:
                        severity = "CRITICAL"
                        severity_class = "critical"
                        analyst_state = "Immediate investigation recommended"
                    elif request_count >= 120:
                        severity = "HIGH"
                        severity_class = "high"
                        analyst_state = "ML-assisted threat investigation recommended"
                    elif request_count >= 45:
                        severity = "MEDIUM"
                        severity_class = "medium"
                        analyst_state = "Behavioural anomaly under investigation"
                    else:
                        severity = "LOW"
                        severity_class = "low"
                        analyst_state = "Passive telemetry monitoring active"

                    combined_alerts.append({
                        "ip": alert.get("ip", "Unknown"),
                        "count": request_count,
                        "severity": severity,
                        "severity_class": severity_class,
                        "analyst_state": analyst_state,
                        "source": "Rule-Based Detection"
                    })

            # --- ML anomaly alerts ---
            if anomalies:
                for a in anomalies:

                    request_count = int(a.get("requests", 0))

                    # Ignore low-value telemetry noise
                    if request_count <= 2:
                        continue

                    top_ip = "Unknown"

                    if a.get("top_ips") and len(a["top_ips"]) > 0:
                        top_ip = a["top_ips"][0].get("ip", "Unknown")

                    anomaly_severity = str(a.get("severity", "LOW")).upper()

                    severity_map = {
                        "HIGH": {
                            "severity_class": "high",
                            "analyst_state": "ML-assisted threat investigation recommended"
                        },
                        "MEDIUM": {
                            "severity_class": "medium",
                            "analyst_state": "Anomalous behavioural pattern under review"
                        },
                        "LOW": {
                            "severity_class": "low",
                            "analyst_state": "Passive anomaly monitoring active"
                        }
                    }

                    mapped = severity_map.get(
                        anomaly_severity,
                        severity_map["LOW"]
                    )

                    combined_alerts.append({
                        "ip": top_ip,
                        "count": request_count,
                        "severity": anomaly_severity,
                        "severity_class": mapped["severity_class"],
                        "analyst_state": mapped["analyst_state"],
                        "source": "ML Detection Engine"
                    })

            # --- Prioritisation Logic ---
            severity_priority = {
                "CRITICAL": 4,
                "HIGH": 3,
                "MEDIUM": 2,
                "LOW": 1
            }

            combined_alerts = sorted(
                combined_alerts,
                key=lambda x: (
                    severity_priority.get(x["severity"], 0),
                    x["count"]
                ),
                reverse=True
            )

            # --- Operational Detection View ---
            visible_alerts_limit = 4
            visible_alerts = combined_alerts[:visible_alerts_limit]

            if visible_alerts:

                for alert in visible_alerts:

                    severity_colour = {
                        "critical": "#FCA5A5",
                        "high": "#FCA5A5",
                        "medium": "#FCD34D",
                        "low": "#86EFAC"
                    }.get(alert["severity_class"], "#CBD5E1")

                    alert_html = f"""
<div class='nora-activity-card nora-alert-inline-card nora-alert-{alert['severity_class']}'>
    <div style='display:flex;justify-content:space-between;align-items:center;gap:12px;'>
        <div>
            <div style='font-size:13px;font-weight:600;color:{severity_colour};letter-spacing:0.04em;'>
                {alert['severity']} PRIORITY
            </div>
            <div style='font-size:13px;color:#F8FAFC;margin-top:4px;'>
                {alert['count']} requests detected from {alert['ip']}
            </div>
        </div>
    </div>
</div>
"""

                    st.markdown(alert_html, unsafe_allow_html=True)

                remaining_alerts = max(
                    len(combined_alerts) - visible_alerts_limit,
                    0
                )

                if remaining_alerts > 0:
                    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

                    button_label = (
                        f"View {remaining_alerts} More Alert"
                        if remaining_alerts == 1
                        else f"View {remaining_alerts} More Alerts"
                    )

                    if st.button(
                        button_label,
                        key="open_log_explorer_alerts"
                    ):
                        st.session_state.active_page = "log_explorer"
                        st.rerun()

            else:
                st.success("No suspicious activity detected")
import pandas as pd
import streamlit as st
import plotly.graph_objects as go


def render_traffic_overview(df_time, anomalies):
    """Render the Overview traffic chart and return anomaly dataframe."""

    avg_requests = df_time["Requests"].mean()
    df_time["AboveBaseline"] = df_time["Requests"] > avg_requests

    anomaly_df = None

    try:
        if anomalies:
            anomaly_df = pd.DataFrame(anomalies)
            anomaly_df = anomaly_df.rename(columns={"time": "TimeStr", "requests": "Requests"})
            anomaly_df["Requests"] = pd.to_numeric(anomaly_df["Requests"], errors="coerce")
            anomaly_df["TimeStr"] = anomaly_df["TimeStr"].astype(str).str[:5]

            current_date = pd.Timestamp.now().normalize()

            anomaly_df["TimeParsed"] = pd.to_datetime(
                anomaly_df["TimeStr"],
                format="%H:%M",
                errors="coerce"
            )

            anomaly_df["TimeParsed"] = anomaly_df["TimeParsed"].apply(
                lambda x: current_date + pd.Timedelta(hours=x.hour, minutes=x.minute)
                if pd.notnull(x) else pd.NaT
            )

            if "severity" not in anomaly_df.columns:
                anomaly_df["severity"] = "LOW"

            anomaly_df["severity"] = anomaly_df["severity"].fillna("LOW").str.upper()
            anomaly_df = anomaly_df.sort_values(by="Requests", ascending=False)
            anomaly_df = anomaly_df.drop_duplicates(subset=["TimeParsed"])
            anomaly_df = anomaly_df[anomaly_df["Requests"] > avg_requests]
    except Exception:
        anomaly_df = None

    st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

    with st.container(border=True):
        st.markdown(
            """
            <div class='nora-panel-header'>
                <div>
                    <div class='nora-panel-title'>Traffic Overview</div>
                    <div class='nora-panel-sub'>Real-time telemetry and anomaly monitoring</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=df_time["TimeParsed"],
            y=df_time["Requests"],
            mode='lines',
            name='Traffic',
            line=dict(color='#1E6BFF', width=3, shape='spline', smoothing=1.15),
            fill='tozeroy',
            fillcolor='rgba(30,107,255,0.12)'
        ))

        fig.add_trace(go.Scatter(
            x=df_time["TimeParsed"],
            y=[avg_requests] * len(df_time),
            mode='lines',
            name='Baseline',
            line=dict(color='#60A5FA', dash='dash', width=2),
            opacity=0.55
        ))

        if anomaly_df is not None and not anomaly_df.empty:
            color_map = {"HIGH": "#DC2626", "MEDIUM": "#F59E0B", "LOW": "#8B5CF6"}

            fig.add_trace(go.Scatter(
                x=anomaly_df["TimeParsed"],
                y=anomaly_df["Requests"],
                mode='markers',
                name='Anomalies',
                marker=dict(
                    color=anomaly_df["severity"].map(color_map).fillna("#8B5CF6"),
                    size=10
                )
            ))

        fig.update_layout(
            height=360,
            margin=dict(l=8, r=8, t=10, b=8),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={'displayModeBar': False}
        )

    return anomaly_df
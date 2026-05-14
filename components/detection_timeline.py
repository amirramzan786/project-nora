import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from src.icons import get_icon

def render_detection_timeline(
    time_counts,
    anomalies
):

    timeline_data = pd.DataFrame({
        "Time Window": list(time_counts.keys()),
        "Requests": list(time_counts.values())
    })

    if not timeline_data.empty:

        timeline_data["Time Window"] = (
            timeline_data["Time Window"]
            .astype(str)
            .str[:5]
        )

        timeline_data["TimeParsed"] = pd.to_datetime(
            timeline_data["Time Window"],
            format="%H:%M",
            errors="coerce"
        )

        timeline_data = timeline_data.sort_values("TimeParsed")

        avg_requests = timeline_data["Requests"].mean()

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=timeline_data["TimeParsed"],
            y=timeline_data["Requests"],
            mode='lines+markers',
            name='Detection Traffic',
            line=dict(color='#2563EB', width=2),
            marker=dict(size=6),
            hovertemplate="<b>Time:</b> %{x|%H:%M}<br><b>Requests:</b> %{y}<extra></extra>"
        ))

        fig.add_trace(go.Scatter(
            x=timeline_data["TimeParsed"],
            y=[avg_requests] * len(timeline_data),
            mode='lines',
            name='Baseline',
            line=dict(color='#60A5FA', dash='dash'),
            hoverinfo='skip'
        ))

        if anomalies:

            anomaly_df = pd.DataFrame(anomalies)

            if not anomaly_df.empty:

                anomaly_df = anomaly_df.rename(
                    columns={
                        "time": "Time Window",
                        "requests": "Requests"
                    }
                )

                anomaly_df["Requests"] = pd.to_numeric(
                    anomaly_df["Requests"],
                    errors="coerce"
                )

                anomaly_df["Time Window"] = (
                    anomaly_df["Time Window"]
                    .astype(str)
                    .str[:5]
                )

                anomaly_df["TimeParsed"] = pd.to_datetime(
                    anomaly_df["Time Window"],
                    format="%H:%M",
                    errors="coerce"
                )

                if "severity" not in anomaly_df.columns:
                    anomaly_df["severity"] = "LOW"

                anomaly_df["severity"] = (
                    anomaly_df["severity"]
                    .fillna("LOW")
                    .str.upper()
                )

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
                        size=12,
                        line=dict(width=1, color='black')
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

        fig.update_layout(
            template='plotly_dark',
            plot_bgcolor='rgba(2,6,23,0)',
            paper_bgcolor='rgba(2,6,23,0)',
            font=dict(color='#E2E8F0', family='Inter'),
            height=520,
            margin=dict(l=10, r=10, t=20, b=10),
            hovermode='x unified'
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={
                'displayModeBar': False,
                'responsive': True
            }
        )

    else:
        st.warning("No detection timeline telemetry available.")
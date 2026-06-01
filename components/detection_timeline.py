import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def render_detection_timeline(
    time_counts,
    anomalies,
    compact_mode=False
):

    timeline_data = pd.DataFrame({
        "Time Window": list(time_counts.keys()),
        "Requests": list(time_counts.values())
    })

    if not timeline_data.empty:

        # --- Phase 2.5 timeline realism calibration ---
        # Prevent Plotly/Pandas from auto-generating Jan 1 1900 timestamps
        # by enforcing clean HH:MM operational labels only.
        timeline_data["Time Window"] = (
            timeline_data["Time Window"]
            .astype(str)
            .str.strip()
            .str[:5]
        )


        avg_requests = timeline_data["Requests"].mean()

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=timeline_data["Time Window"],
            y=timeline_data["Requests"],
            mode='lines',
            name='Detection Traffic',
            line=dict(
                color='#1E6BFF',
                width=3,
                shape='spline',
                smoothing=1.15
            ),
            fill='tozeroy',
            fillcolor='rgba(30,107,255,0.12)',
            hovertemplate="<b>Time:</b> %{x}<br><b>Requests:</b> %{y}<extra></extra>"
        ))

        fig.add_trace(go.Scatter(
            x=timeline_data["Time Window"],
            y=[avg_requests] * len(timeline_data),
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

        # =====================================================
        # Phase 2.5E — Operational timeline intelligence overlays
        # =====================================================

        escalation_x = []
        escalation_y = []

        investigation_x = []
        investigation_y = []

        monitoring_x = []
        monitoring_y = []

        peak_value = timeline_data["Requests"].max()

        for _, row in timeline_data.iterrows():

            timestamp = row["Time Window"]
            value = row["Requests"]

            if value >= peak_value * 0.85:
                escalation_x.append(timestamp)
                escalation_y.append(value)

            elif value >= peak_value * 0.55:
                investigation_x.append(timestamp)
                investigation_y.append(value)

            else:
                monitoring_x.append(timestamp)
                monitoring_y.append(value)

        # --- Escalation markers ---
        if escalation_x:
            fig.add_trace(go.Scatter(
                x=escalation_x,
                y=escalation_y,
                mode='markers',
                name='Escalation Events',
                marker=dict(
                    size=11,
                    color='#EF4444',
                    symbol='diamond'
                ),
                hovertemplate=(
                    '<b>Escalation Event</b><br>'
                    'Time: %{x}<br>'
                    'Traffic: %{y}<extra></extra>'
                )
            ))

        # --- Investigation markers ---
        if investigation_x:
            fig.add_trace(go.Scatter(
                x=investigation_x,
                y=investigation_y,
                mode='markers',
                name='Investigation Triggers',
                marker=dict(
                    size=8,
                    color='#F59E0B',
                    symbol='circle'
                ),
                hovertemplate=(
                    '<b>Investigation Trigger</b><br>'
                    'Time: %{x}<br>'
                    'Traffic: %{y}<extra></extra>'
                )
            ))

        # --- Monitoring markers ---
        if monitoring_x:
            fig.add_trace(go.Scatter(
                x=monitoring_x,
                y=monitoring_y,
                mode='markers',
                name='Monitoring States',
                marker=dict(
                    size=6,
                    color='#22C55E',
                    symbol='circle-open'
                ),
                hovertemplate=(
                    '<b>Monitoring State</b><br>'
                    'Time: %{x}<br>'
                    'Traffic: %{y}<extra></extra>'
                )
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
                    .str.strip()
                    .str[:5]
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
                    x=anomaly_df["Time Window"],
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
                        "Time: %{x}<br>"
                        "Requests: %{y}<br>"
                        "Severity: %{text}<extra></extra>"
                    ),
                    text=anomaly_df["severity"],
                    legendgroup='anomalies',
                    showlegend=False
                ))

                fig.add_trace(go.Scatter(
                    x=[None],
                    y=[None],
                    mode='markers',
                    name='High Severity',
                    marker=dict(
                        size=10,
                        color='#DC2626'
                    ),
                    hoverinfo='skip'
                ))

                fig.add_trace(go.Scatter(
                    x=[None],
                    y=[None],
                    mode='markers',
                    name='Medium Severity',
                    marker=dict(
                        size=10,
                        color='#F59E0B'
                    ),
                    hoverinfo='skip'
                ))

                fig.add_trace(go.Scatter(
                    x=[None],
                    y=[None],
                    mode='markers',
                    name='Low Severity',
                    marker=dict(
                        size=10,
                        color='#8B5CF6'
                    ),
                    hoverinfo='skip'
                ))

        fig.update_layout(
            height=300 if compact_mode else 420,
            margin=dict(l=8, r=8, t=45, b=8),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            hovermode='x unified',
            shapes=[
                {
                    'type': 'line',
                    'xref': 'paper',
                    'x0': 0,
                    'x1': 1,
                    'y0': peak_value * 0.85,
                    'y1': peak_value * 0.85,
                    'line': {
                        'color': 'rgba(239,68,68,0.30)',
                        'width': 1,
                        'dash': 'dot'
                    }
                },
                {
                    'type': 'line',
                    'xref': 'paper',
                    'x0': 0,
                    'x1': 1,
                    'y0': peak_value * 0.55,
                    'y1': peak_value * 0.55,
                    'line': {
                        'color': 'rgba(245,158,11,0.26)',
                        'width': 1,
                        'dash': 'dot'
                    }
                }
            ],
            annotations=[
                {
                    'x': 1,
                    'xref': 'paper',
                    'y': peak_value * 0.85,
                    'yref': 'y',
                    'text': 'Escalation Threshold',
                    'showarrow': False,
                    'font': {
                        'size': 10,
                        'color': 'rgba(239,68,68,0.82)'
                    }
                },
                {
                    'x': 1,
                    'xref': 'paper',
                    'y': peak_value * 0.55,
                    'yref': 'y',
                    'text': 'Investigation Threshold',
                    'showarrow': False,
                    'font': {
                        'size': 10,
                        'color': 'rgba(245,158,11,0.82)'
                    }
                }
            ],
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
                y=1.12,
                xanchor='right',
                x=1,
                bgcolor='rgba(0,0,0,0)',
                font=dict(
                    size=11,
                    color='#CBD5E1'
                )
            )
        )

        # --- Phase 2.5 operational readability calibration ---
        # Reduce overcrowded SOC timeline labels and improve
        # analyst-facing telemetry readability.

        tick_interval = max(
            1,
            int(len(timeline_data) / 8)
        )

        visible_ticks = timeline_data["Time Window"].iloc[::tick_interval]

        fig.update_xaxes(
            showgrid=False,
            zeroline=False,
            showline=False,
            tickfont=dict(
                color='#94A3B8',
                size=10
            ),
            tickmode='array',
            tickvals=visible_ticks,
            tickangle=0,
            type='category',
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
import pandas as pd
import streamlit as st

from components.ui_helpers import render_section_title
from components.detection_sources_table import render_detection_sources_table
from src.threat_source_intelligence import build_threat_source_rows


def render_detection_sources_section(
    ip_totals,
    active_alerts,
    avg_requests,
    overall_severity,
    estimated_confidence,
):
    """Render the observed Detection Sources section."""

    with st.container(border=True):
        render_section_title(
            'fc_radar_plot',
            'Detection Sources'
        )

        st.markdown(
            "<div class='nora-workspace-spacing-sm'></div>",
            unsafe_allow_html=True
        )

        if ip_totals:
            top_ips = sorted(
                ip_totals.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]

            threat_rows, _ = build_threat_source_rows(
                top_ips,
                ip_totals,
                active_alerts,
                avg_requests,
                overall_severity,
                estimated_confidence
            )

            detection_sources_df = pd.DataFrame(threat_rows)

            render_detection_sources_table(
                detection_sources_df,
                estimated_confidence
            )

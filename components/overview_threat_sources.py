

import os
import pandas as pd
import streamlit as st

from src.icons import get_icon
from src.feedback import save_feedback


def render_overview_threat_sources(ip_totals, anomalies, right_side_modules):
    """Render the Overview right-side intelligence column."""

    st.markdown("<div style='height:18px;'></div>", unsafe_allow_html=True)

    with st.container(border=True):
        st.markdown(
            f"<div class='nora-intel-title'>{get_icon('shield')}Threat Source Intelligence</div>",
            unsafe_allow_html=True
        )

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
                ).properties(background=chart_bg)

                st.write("Top IP Activity")
                st.altair_chart(chart_ips, use_container_width=True)
        except Exception:
            pass

        try:
            if right_side_modules:
                with st.expander("Advanced Analysis"):
                    st.markdown(f"""
- Similarity Match: {right_side_modules['similarity']}%
- Z-Score: {right_side_modules['z_score']} ({right_side_modules['z_label']})
- Severity Context: {right_side_modules['severity_reason']}
""")

                with st.expander("ML Anomaly Insights (Optional Analyst View)"):
                    for a in right_side_modules['anomalies'][:3]:
                        st.markdown(f"**Severity:** {(a.get('severity') or 'LOW').upper()}")
                        st.markdown(f"**Time:** {a.get('time', 'Unknown')}")
                        st.markdown(f"**Confidence:** {a.get('confidence', 0)}%")
                        st.markdown("---")
        except Exception:
            pass
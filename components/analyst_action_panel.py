import time
import streamlit as st
import streamlit.components.v1 as components

from components.operational_cards import (
    render_analyst_action_card,
    OPERATIONAL_IFRAME_CSS,
)

def render_analyst_action_panel():
    
    # --- Analyst Action section moved to a new bordered container ---
    with st.container(border=True):
        st.markdown("### Analyst Action")

        st.caption(
            "Operational response actions, escalation routing and analyst-assisted workflow controls."
        )

        analyst_col1, analyst_col2, analyst_col3, analyst_col4 = st.columns(4)

        with analyst_col1:
            components.html(
                f"""
                <style>{OPERATIONAL_IFRAME_CSS}</style>

                {render_analyst_action_card(
                    'shield',
                    'high',
                    'Escalation',
                    'Route suspicious detection activity into the SOC escalation workflow.',
                    'Priority Escalation Path',
                    'Escalate Detection'
                )}
                """,
                height=270,
                scrolling=False
            )

        with analyst_col2:
            components.html(
                f"""
                <style>{OPERATIONAL_IFRAME_CSS}</style>

                {render_analyst_action_card(
                    'search',
                    'medium',
                    'Investigation',
                    'Initiate source telemetry analysis and operational investigation workflow.',
                    'Investigation Workflow Active',
                    'Investigate Source IP'
                )}
                """,
                height=270,
                scrolling=False
            )

        with analyst_col3:
            components.html(
                f"""
                <style>{OPERATIONAL_IFRAME_CSS}</style>

                {render_analyst_action_card(
                    'activity',
                    'low',
                    'Classification',
                    'Classify traffic behaviour and operational detection legitimacy.',
                    'Benign Classification Available',
                    'Mark As Benign'
                )}
                """,
                height=270,
                scrolling=False
            )

        with analyst_col4:
            components.html(
                f"""
                <style>{OPERATIONAL_IFRAME_CSS}</style>

                {render_analyst_action_card(
                    'brain',
                    'medium',
                    'Learning Engine',
                    'Submit telemetry into the adaptive intelligence learning pipeline.',
                    'Adaptive Learning Queue',
                    'Add To Learning Engine'
                )}
                """,
                height=270,
                scrolling=False
            )

        if "analyst_actions" not in st.session_state:
            st.session_state.analyst_actions = []
        if st.session_state.analyst_actions:

            st.markdown("<div class='nora-workspace-spacing'></div>", unsafe_allow_html=True)

            latest_action = st.session_state.analyst_actions[-1]

            success_placeholder = st.empty()

            success_placeholder.success(latest_action)

            time.sleep(2)

            success_placeholder.empty()

        st.caption(
            "Adaptive ML-assisted detection classification (Placeholder) scheduled for Phase 4 intelligence expansion."
        )
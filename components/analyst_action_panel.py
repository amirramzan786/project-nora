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
        st.markdown("### Analyst Validation & Feedback")

        st.caption(
            "Analyst validation workflow supporting detection verification, review decisions and adaptive learning feedback."
        )

        analyst_col1, analyst_col2, analyst_col3, analyst_col4 = st.columns(4)

        with analyst_col1:
            components.html(
                f"""
                <style>{OPERATIONAL_IFRAME_CSS}</style>

                {render_analyst_action_card(
                    'shield',
                    'high',
                    'Confirm Detection',
                    'Validate the detection as legitimate suspicious behavioural activity.',
                    'Detection Confirmed',
                    'Confirm Detection'
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
                    'Needs Review',
                    'Detection requires additional investigation before final classification.',
                    'Review Assessment Pending',
                    'Flag For Review'
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
                    'False Positive',
                    'Detection determined to be benign or non-malicious activity.',
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
                    'Learning Feedback',
                    'Submit analyst assessment to the adaptive intelligence feedback engine.',
                    'Adaptive Learning Available',
                    'Submit Feedback'
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
            "Future adaptive learning integration will use analyst validation outcomes to support confidence reinforcement, similarity scoring and behavioural memory analysis."
        )
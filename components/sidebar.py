import streamlit as st


NAV_ITEMS = [
    ("overview", "Overview"),
    ("detection_intelligence", "Detection Intelligence Center"),
    ("threat_intelligence", "Threat Intelligence Center"),
    ("network_traffic", "Network Traffic Analysis"),
    ("adaptive_intelligence", "Adaptive Intelligence Engine"),
    ("detection_performance", "Detection Performance Center"),
    ("log_explorer", "Log Explorer"),
]

def render_sidebar():
    """Render the N.O.R.A sidebar navigation and return the active page."""

    if "active_page" not in st.session_state:
        st.session_state.active_page = "overview"

    with st.sidebar:
        st.image("logo.png")

        st.markdown(
            """
            <div class='nora-sidebar-brand'>
                <p>Network Observation & Response Assistant</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("---")

        for page_key, page_label in NAV_ITEMS:
            button_type = (
                "primary"
                if st.session_state.active_page == page_key
                else "secondary"
            )

            if st.button(page_label, use_container_width=True, type=button_type):
                st.session_state.active_page = page_key
                st.rerun()

    return st.session_state.active_page

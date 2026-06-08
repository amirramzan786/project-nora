import streamlit as st

NAV_ITEMS = [
    {
        "section": "Core",
        "items": [
            ("overview", "⌂", "Overview", "Platform overview & operational telemetry"),
            ("log_explorer", "▣", "Log Explorer", "Search and investigate log events"),
        ]
    },
    {
        "section": "Intelligence",
        "items": [
            ("detection_intelligence", "◬", "Detection Intel", "Behavioural detection analytics"),
            ("threat_intelligence", "◉", "Threat Intel", "Threat enrichment & correlation"),
            ("adaptive_intelligence", "⬡", "Adaptive Intel", "Adaptive behavioural analysis"),
        ]
    },
]

def render_navigation():

    current_page = st.query_params.get("page", "overview")

    left_spacer, logo_col, right_spacer = st.columns([1, 2, 1])

    with logo_col:
        st.image("logo.png", width=140)

    st.markdown(
        """
        <div class='nora-sidebar-subtitle'>
            Network Operational Research Assistant
        </div>
        """,
        unsafe_allow_html=True
    )

    for section_group in NAV_ITEMS:

        section_name = section_group["section"]

        st.markdown(
            f"""
            <div class='nora-nav-section'>
                {section_name}
            </div>
            """,
            unsafe_allow_html=True
        )

        for key, icon, label, tooltip in section_group["items"]:

            is_active = key == current_page
            button_type = "primary" if is_active else "secondary"
            button_label = f"{icon}\n{label}"

            if st.button(
                button_label,
                key=f"nav_{key}",
                use_container_width=True,
                type=button_type,
                help=tooltip,
            ):
                st.query_params.clear()
                st.query_params["page"] = key
                st.rerun()


    st.markdown(
        """
        <div class='nora-sidebar-footer'>
            <div class='nora-sidebar-status'>SYSTEM ONLINE</div>
            <div class='nora-sidebar-version'>N.O.R.A v1.0.0</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    return current_page
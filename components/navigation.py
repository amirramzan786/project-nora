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
    """Render the primary workspace navigation as native HTML links.

    This avoids Streamlit radio/segmented-control hitbox issues and keeps
    navigation stable because each tab is a normal browser anchor.
    """

    current_page = st.query_params.get("page", "overview")

    flat_nav_items = []
    for section_group in NAV_ITEMS:
        flat_nav_items.extend(section_group["items"])

    valid_pages = {key for key, _, _, _ in flat_nav_items}
    if current_page not in valid_pages:
        current_page = "overview"

    nav_links = []
    for key, icon, label, description in flat_nav_items:
        active_class = " active" if key == current_page else ""
        nav_links.append(
            f"""
            <a class="nora-top-nav-item{active_class}" href="?page={key}" title="{description}">
                <span class="nora-top-nav-icon">{icon}</span>
                <span class="nora-top-nav-label">{label}</span>
            </a>
            """
        )

    nav_html = f'''
    <div class="nora-app-shell-nav">
        <nav class="nora-top-nav" aria-label="Workspace navigation">
            {"".join(nav_links)}
        </nav>
    </div>
    '''
    st.html(nav_html)

    return current_page
# Operational telemetry icon renderer.
# -----------------------------------------------------
# Used by custom N.O.R.A operational cards and telemetry
# surfaces that need local inline SVGs with severity-aware
# colouring.
#
# NOTE:
# This file should remain separate from src/icons.py, which
# owns general inline UI/heading icons via get_icon(...).
# -----------------------------------------------------

def render_operational_icon(icon_type='activity', severity='low'):

    severity_colours = {
        'low': '#22C55E',
        'medium': '#F59E0B',
        'high': '#EF4444'
    }

    icon_colour = severity_colours.get(
        severity,
        '#2596BE'
    )

    icon_map = {
        'activity': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
        ''',

        'shield': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        ''',

        'satellite': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M13 7 9 3 5 7l4 4"/>
                <path d="m17 11 4 4-4 4-4-4"/>
                <path d="m8 12 4 4"/>
                <path d="m16 8-4 4"/>
                <path d="M9 3 3 9"/>
                <path d="m21 15-6 6"/>
            </svg>
        ''',

        'logs': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M4 6h16"/>
                <path d="M4 12h16"/>
                <path d="M4 18h10"/>
            </svg>
        ''',

        'alerts': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        ''',

        'warning': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        ''',

        'elevated': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/>
                <polyline points="16 7 22 7 22 13"/>
            </svg>
        ''',

        'brain': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M9.5 2a3.5 3.5 0 0 0-3.5 3.5V7a3 3 0 0 0-2 2.83A3 3 0 0 0 6 12.66V14a3 3 0 0 0 3 3h1v3"/>
                <path d="M14.5 2A3.5 3.5 0 0 1 18 5.5V7a3 3 0 0 1 2 2.83A3 3 0 0 1 18 12.66V14a3 3 0 0 1-3 3h-1v3"/>
            </svg>
        ''',

        'target': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="8"/>
                <circle cx="12" cy="12" r="4"/>
                <circle cx="12" cy="12" r="1"/>
            </svg>
        ''',

        'server': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="4" width="18" height="6" rx="1"/>
                <rect x="3" y="14" width="18" height="6" rx="1"/>
                <line x1="7" y1="7" x2="7.01" y2="7"/>
                <line x1="7" y1="17" x2="7.01" y2="17"/>
            </svg>
        ''',

        'globe': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <path d="M2 12h20"/>
                <path d="M12 2a15 15 0 0 1 0 20"/>
                <path d="M12 2a15 15 0 0 0 0 20"/>
            </svg>
        ''',

        'link': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11 5"/>
                <path d="M14 11a5 5 0 0 0-7.07 0L4.1 13.83a5 5 0 1 0 7.07 7.07L13 19"/>
            </svg>
        ''',

        'clipboard': '''
            <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="8" y="2" width="8" height="4" rx="1"/>
                <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
            </svg>
        ''',
    }

    icon_svg = icon_map.get(
        icon_type,
        icon_map['activity']
    )

    cleaned_svg = icon_svg.strip()

    return f'''
    <span class="nora-operational-zone-icon" style="
        color:{icon_colour};
        display:flex;
        align-items:center;
        justify-content:center;
        min-width:28px;
    ">
        {cleaned_svg}
    </span>
    '''.strip()


def render_telemetry_card(
    title,
    value,
    subtext,
    icon_html="",
    extra_class=""
):

    return (
        f'<div class="nora-threat-stat {extra_class}">'
        f'<div class="nora-threat-stat-label" style="display:flex;align-items:center;gap:10px;">{icon_html}<span>{title}</span></div>'
        f'<div class="nora-threat-stat-value">{value}</div>'
        f'<div class="nora-threat-stat-subtext">{subtext}</div>'
        f'</div>'
    )
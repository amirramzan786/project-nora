from textwrap import dedent


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
        '''
    }

    icon_svg = icon_map.get(
        icon_type,
        icon_map['activity']
    )

    return dedent(f'''
        <div class="nora-operational-zone-icon" style="
            color:{icon_colour};
            box-shadow:0 0 18px rgba(37,150,190,0.10);
        ">
            {icon_svg}
        </div>
    ''')

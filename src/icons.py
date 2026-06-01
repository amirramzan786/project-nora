# Shared inline UI icon registry.
# -----------------------------------------------------
# Used by workspace headings, labels, panels and compact
# inline icon surfaces via get_icon(...).
#
# NOTE:
# This file currently uses Iconify-hosted Lucide SVG URLs.
# It should remain separate from components/icons.py, which
# owns local operational SVG telemetry/card icons.
# -----------------------------------------------------

SVG_ICONS = {
    "database": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/database.svg' />",
    "shield_alert": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/shield-alert.svg' />",
    "shield": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/shield.svg' />",
    "timer": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/timer-reset.svg' />",
    "activity": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/activity.svg' />",
    "brain": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/brain-circuit.svg' />",
    "alert_triangle": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/alert-triangle.svg' />",
    "check_circle": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/check-circle.svg' />",
    "shield_warning": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/shield-alert.svg' />",
    "bar_chart": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/chart-column.svg' />",
    "globe": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/globe.svg' />",
    "clock": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/clock-3.svg' />",
    "folder": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/folder.svg' />",
    "search": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/search.svg' />",
    "crosshair": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/crosshair.svg' />",
    "target": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/crosshair.svg' />",
    "server": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/server.svg' />",
    "link": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/link.svg' />",
    "clipboard": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/clipboard-list.svg' />",
    "siren": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/siren.svg' />",
    "triangle_alert": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/triangle-alert.svg' />",
    "notifications": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/bell-ring.svg' />",
    "pie_chart": "<img class='nora-inline-svg' src='https://api.iconify.design/lucide/chart-pie.svg' />"
}


def get_icon(name):
    return SVG_ICONS.get(name, "")
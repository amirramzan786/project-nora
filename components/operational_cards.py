import streamlit as st
import streamlit.components.v1 as components
from components.icons import render_operational_icon

from pathlib import Path

OPERATIONAL_IFRAME_CSS = Path(
    "assets/operational_cards.css"
).read_text()

def render_operational_hero_card(overall_severity="HIGH"):

    components.html(
        f"""
        <style>{OPERATIONAL_IFRAME_CSS}</style>

        <div class='nora-operational-hero'>

            <div class='nora-operational-hero-icon'>
                {render_operational_icon('activity', 'high')}
            </div>

            <div class='nora-operational-hero-content'>

                <div class='nora-operational-hero-title'>
                    {overall_severity.title()} Severity Detection Activity
                </div>

                <div class='nora-operational-hero-text'>
                    {
                        'Current network telemetry indicates sustained anomalous behaviour, elevated escalation readiness and coordinated threat conditions requiring analyst attention.'
                        if overall_severity in ['HIGH', 'CRITICAL']
                        else 'Current telemetry indicates elevated behavioural irregularities requiring continued analyst observation and monitoring.'
                    }
                </div>

            </div>

        </div>
        """,
        height=150,
        scrolling=False
    )

def render_threat_assessment_card(
    overall_severity,
    threat_summary
):
    severity = str(overall_severity).upper()

    severity_colour_map = {
        'LOW': '#22C55E',
        'MEDIUM': '#F59E0B',
        'HIGH': '#EF4444',
        'CRITICAL': '#EF4444'
    }

    severity_subtitle_map = {
        'LOW': 'Low Risk',
        'MEDIUM': 'Elevated Risk',
        'HIGH': 'High Risk',
        'CRITICAL': 'Critical Risk'
    }

    severity_guidance_map = {
        'LOW': (
            '● No immediate threat detected<br>'
            '● Baseline traffic behaviour<br>'
            '● Continue passive monitoring'
        ),
        'MEDIUM': (
            '● Suspicious behavioural activity detected<br>'
            '● Elevated traffic irregularities observed<br>'
            '● Analyst monitoring recommended'
        ),
        'HIGH': (
            '● Coordinated suspicious behaviour observed<br>'
            '● Sustained anomalous traffic detected<br>'
            '● Escalation and investigation required'
        ),
        'CRITICAL': (
            '● Active attack conditions identified<br>'
            '● Severe operational impact risk detected<br>'
            '● Immediate SOC response required'
        )
    }

    severity_colour = severity_colour_map.get(severity, '#22C55E')
    severity_subtitle = severity_subtitle_map.get(severity, 'Monitoring Active')
    severity_guidance = severity_guidance_map.get(
        severity,
        severity_guidance_map['LOW']
    )

    components.html(
        f"""
        <style>{OPERATIONAL_IFRAME_CSS}</style>
        <div class='nora-operational-card'>

            <div class='nora-operational-label' style='margin-bottom:8px;'>
                Threat Assessment
            </div>

            <div class='nora-operational-module'>

                {render_operational_icon('activity', severity.lower())}

                <div class='nora-operational-zone-main'>

                    <div class='nora-operational-zone-top'>

                        <div class='nora-operational-state-large' style='color:{severity_colour};'>
                            {severity}
                        </div>

                        <div class='nora-operational-state-subtitle'>
                            {severity_subtitle}
                        </div>

                    </div>

                    <div class='nora-operational-guidance-panel'>

                        <div class='nora-operational-guidance'>
                            {severity_guidance}
                        </div>

                    </div>

                </div>

            </div>

            <div class='nora-operational-divider'></div>

            <div class='nora-operational-grid'>

                <div>
                    <div class='nora-operational-label'>Confidence</div>
                    <div class='nora-operational-value'>Adaptive</div>
                </div>

                <div>
                    <div class='nora-operational-label'>Last Updated</div>
                    <div class='nora-operational-value'>2m ago</div>
                </div>

            </div>

        </div>
        """,
        height=340,
        scrolling=False
    )

# =========================
# Analyst Action Card Renderer (Reusable)
# =========================
def render_analyst_action_card(
    icon_type,
    severity,
    title,
    description,
    status,
    button_label
):

    return f"""
        <div class='nora-analyst-module'>

            <div class='nora-analyst-header'>
                {render_operational_icon(icon_type, severity)}

                <div class='nora-analyst-title'>
                    {title}
                </div>
            </div>

            <div class='nora-analyst-description'>
                {description}
            </div>

            <div class='nora-analyst-status'>
                {status}
            </div>

            <div class='nora-analyst-action-button'>
                {button_label}
            </div>

        </div>
    """
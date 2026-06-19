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

def render_escalation_guidance_card(escalation_summary):

    escalation_priority_map = {
        'P1': 'high',
        'P2': 'high',
        'P3': 'medium',
        'P4': 'low'
    }

    escalation_priority = escalation_priority_map.get(
        escalation_summary['response_priority'],
        'info'
    )

    escalation_colour_map = {
        'P1': '#EF4444',
        'P2': '#F97316',
        'P3': '#F59E0B',
        'P4': '#22C55E'
    }

    escalation_status_map = {
        'P1': 'Critical Escalation',
        'P2': 'Priority Investigation',
        'P3': 'Active Monitoring',
        'P4': 'Monitoring Active'
    }

    escalation_guidance_map = {
        'P1': (
            '● Immediate analyst escalation required.<br>'
            '● Incident response workflow active'
        ),
        'P2': (
            '● Elevated threat behaviour detected.<br>'
            '● Priority investigation recommended'
        ),
        'P3': (
            '● Suspicious behaviour under review.<br>'
            '● Continue analyst monitoring'
        ),
        'P4': (
            '● Operational thresholds stable.<br>'
            '● Continue monitoring'
        )
    }

    escalation_colour = escalation_colour_map.get(
        escalation_summary['response_priority'],
        '#22C55E'
    )

    escalation_status = escalation_status_map.get(
        escalation_summary['response_priority'],
        'Monitoring Active'
    )

    escalation_guidance = escalation_guidance_map.get(
        escalation_summary['response_priority'],
        escalation_guidance_map['P4']
    )

    components.html(
        f"""
        <style>{OPERATIONAL_IFRAME_CSS}</style>
        <div class='nora-operational-card'>

            <div class='nora-operational-label' style='margin-bottom:8px;'>
                Escalation Guidance
            </div>

            <div class='nora-operational-module'>

                {render_operational_icon('shield', escalation_priority)}

                <div class='nora-operational-zone-main'>

                    <div class='nora-operational-zone-top'>

                        <div class='nora-operational-state-large' style='color:{escalation_colour};'>
                            {escalation_summary['response_priority']}
                        </div>

                        <div class='nora-operational-state-subtitle'>
                            {escalation_status}
                        </div>

                    </div>

                    <div class='nora-operational-guidance-panel'>

                        <div class='nora-operational-guidance'>
                            {escalation_guidance}
                        </div>

                    </div>

                </div>

            </div>

            <div class='nora-operational-divider'></div>

            <div class='nora-operational-grid'>

                <div>
                    <div class='nora-operational-label'>Analyst Priority</div>
                    <div class='nora-operational-value'>
                        {escalation_summary['response_priority']}
                    </div>
                </div>

                <div>
                    <div class='nora-operational-label'>Review</div>
                    <div class='nora-operational-value'>15 min</div>
                </div>

            </div>

        </div>
        """,
        height=340,
        scrolling=False
    )

def render_notification_workflow_card(notification_summary):

    notification_priority_map = {
        'Critical': 'high',
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low'
    }

    notification_priority = notification_priority_map.get(
        notification_summary['notification_priority'],
        'info'
    )

    soc_notify = (
        'YES'
        if notification_summary['notify_soc']
        else 'NO'
    )

    acknowledgement_required = (
        'REQUIRED'
        if notification_summary['requires_acknowledgement']
        else 'NOT REQUIRED'
    )

    channels = (
        ', '.join(notification_summary['channels'])
        if notification_summary['channels']
        else 'None'
    )

    workflow_steps = notification_summary.get(
        'workflow_stages',
        [
            'Detection',
            'Behaviour Analysis',
            'Pattern Correlation',
            'Threat Assessment',
            'Analyst Review'
        ]
    )

    workflow_progress = (
        'Analyst review active. Behavioural indicators have exceeded escalation thresholds and require validation before response recommendations are issued.'
        if notification_summary['notification_priority'] == 'Critical'
        else 'Threat assessment in progress. Correlated indicators suggest elevated behavioural risk requiring analyst evaluation.'
        if notification_summary['notification_priority'] == 'High'
        else 'Pattern correlation underway. Current anomalies are being compared against observed behavioural activity.'
        if notification_summary['notification_priority'] == 'Medium'
        else 'Behaviour analysis active. Telemetry is being evaluated for deviations from established baseline behaviour.'
    )

    workflow_status = (
        'ANALYST REVIEW'
        if notification_summary['notification_priority'] == 'Critical'
        else 'THREAT ASSESSMENT'
        if notification_summary['notification_priority'] == 'High'
        else 'PATTERN CORRELATION'
        if notification_summary['notification_priority'] == 'Medium'
        else 'BEHAVIOUR ANALYSIS'
    )

    # =====================================================
    # Phase 2.5F — Workflow operational realism diversification
    # =====================================================

    analyst_owner = {
        'Critical': 'Lead Security Analyst',
        'High': 'Threat Analyst',
        'Medium': 'Detection Analyst',
        'Low': 'Behaviour Monitor'
    }.get(
        notification_summary['notification_priority'],
        'Detection Analyst'
    )

    workflow_eta = {
        'Critical': '< 5 min',
        'High': '15 min',
        'Medium': '30 min',
        'Low': 'Passive'
    }.get(
        notification_summary['notification_priority'],
        '30 min'
    )

    workflow_completion = {
        'Critical': 'Analyst review remains active while behavioural evidence is validated and response recommendations are prepared.',
        'High': 'Threat assessment remains active pending completion of correlation and analyst review activities.',
        'Medium': 'Pattern correlation is progressing as anomalous activity is compared against historical observations.',
        'Low': 'Behaviour analysis remains active while telemetry continues to be assessed against baseline conditions.'
    }.get(
        notification_summary['notification_priority'],
        'Pattern correlation is progressing as anomalous activity is compared against historical observations.'
    )

    queue_state = {
        'Critical': 'Analyst Review Queue',
        'High': 'Threat Assessment Queue',
        'Medium': 'Pattern Correlation Queue',
        'Low': 'Behaviour Analysis Queue'
    }.get(
        notification_summary['notification_priority'],
        'Pattern Correlation Queue'
    )

    active_stage_map = {
        'Critical': 'Analyst Review',
        'High': 'Threat Assessment',
        'Medium': 'Pattern Correlation',
        'Low': 'Behaviour Analysis'
    }

    active_stage = active_stage_map.get(
        notification_summary['notification_priority'],
        workflow_steps[-1]
    )

    active_index = (
        workflow_steps.index(active_stage)
        if active_stage in workflow_steps
        else len(workflow_steps) - 1
    )

    workflow_timestamps = []

    for index, step in enumerate(workflow_steps):

        if step == active_stage:
            workflow_timestamps.append('ACTIVE')
        else:
            workflow_timestamps.append(
                f"13:{42 + index:02d} UTC"
            )

    workflow_pipeline = ''.join([
        f'''
        <div style="
            display:flex;
            align-items:center;
            gap:8px;
        ">

            <div style="
                padding:8px 12px;
                border-radius:12px;
                min-width:130px;
                text-align:center;

                border:{'1px solid rgba(96,165,250,0.45)' if index == active_index else '1px solid rgba(37,150,190,0.18)' if index < active_index else '1px solid rgba(148,163,184,0.08)'};

                background:{'linear-gradient(180deg, rgba(59,130,246,0.20) 0%, rgba(37,99,235,0.14) 100%)' if index == active_index else 'rgba(15,23,42,0.36)' if index < active_index else 'rgba(15,23,42,0.18)'};

                color:{'#F8FAFC' if index <= active_index else 'rgba(148,163,184,0.55)'};
                font-size:12px;
                font-weight:700;
                opacity:{'1' if index <= active_index else '0.55'};
            ">

                <div>
                    {step}
                </div>

                <div style="
                    margin-top:4px;
                    font-size:10px;
                    color:{'#93C5FD' if index == active_index else 'rgba(148,163,184,0.60)'};
                ">
                    {'ACTIVE' if index == active_index else 'COMPLETE' if index < active_index else 'PENDING'}
                </div>

            </div>

            {
                '<div style="color:rgba(96,165,250,0.25);font-size:12px;">→</div>'
                if step != workflow_steps[-1]
                else ''
            }

        </div>
        '''
        for index, step in enumerate(workflow_steps)
    ])

    components.html(
        f"""
        <style>{OPERATIONAL_IFRAME_CSS}</style>

        <div class='nora-operational-card'>

            <div class='nora-operational-label' style='margin-bottom:16px;'>
                Notification Workflow
            </div>

            <div class='nora-workflow-status-row'>

                <div class='nora-status-pill {notification_priority}'>
                    Workflow: {workflow_status}
                </div>

                <div class='nora-status-pill {notification_priority}'>
                    Priority: {notification_summary['notification_priority']}
                </div>

                <div class='nora-status-pill {notification_priority}'>
                    SOC Notify: {soc_notify}
                </div>

                <div class='nora-status-pill {notification_priority}'>
                    Acknowledgement: {acknowledgement_required}
                </div>

            </div>

            <div class='nora-workflow-pipeline-wrapper'>
                {workflow_pipeline}
            </div>

            <div class='nora-workflow-info-grid'>

    <div class='nora-workflow-info-card'>
        <div class='nora-operational-label'>Analyst Owner</div>
        <div class='nora-operational-value' style='font-size:16px;color:#F8FAFC;'>
            {analyst_owner}
        </div>
    </div>

    <div class='nora-workflow-info-card'>
        <div class='nora-operational-label'>Queue State</div>
        <div class='nora-operational-value' style='font-size:16px;color:#F8FAFC;'>
            {queue_state}
        </div>
    </div>

    <div class='nora-workflow-info-card'>
        <div class='nora-operational-label'>Response ETA</div>
        <div class='nora-operational-value' style='font-size:18px;font-weight:800;color:#93C5FD;'>
            {workflow_eta}
        </div>
    </div>

    <div class='nora-workflow-info-card'>
        <div class='nora-operational-label'>Workflow State</div>
        <div class='nora-operational-value' style='font-size:16px;color:#F8FAFC;'>
            {workflow_status.title()}
        </div>
    </div>

</div>

            <div class='nora-investigation-lifecycle-panel'>

    <div class='nora-operational-label' style='margin-bottom:8px;'>
        Investigation Lifecycle
    </div>

    <div class='nora-operational-guidance' style='margin-bottom:12px;'>
        {workflow_progress}
    </div>

    <div class='nora-investigation-lifecycle-divider'></div>

    <div class='nora-operational-guidance'>
        {workflow_completion}
    </div>

</div>

            <div class='nora-notification-grid'>

                <div class='nora-notification-module'>

                    {render_operational_icon('satellite', notification_priority)}

                    <div class='nora-notification-state'>

                        <div class='nora-notification-title'>
                            Notification Channels
                        </div>

                        <div class='nora-notification-subtitle'>
                            Active Routing
                        </div>

                    </div>

                    <div class='nora-notification-divider'></div>

                    <div class='nora-notification-text'>
                        {channels}
                    </div>

                </div>

                <div class='nora-notification-module'>

                    {render_operational_icon('shield', notification_priority)}

                    <div class='nora-notification-state'>

                        <div class='nora-notification-title'>
                            Analyst Guidance
                        </div>

                        <div class='nora-notification-subtitle'>
                            Recommended Action
                        </div>

                    </div>

                    <div class='nora-notification-divider'></div>

                    <div class='nora-notification-text'>
                        {notification_summary['recommended_action']}
                    </div>

                </div>

            </div>

        </div>
        """,
        height=705,
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
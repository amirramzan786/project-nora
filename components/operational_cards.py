import streamlit as st
import streamlit.components.v1 as components
from components.icons import render_operational_icon

CARD_STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

html, body {
    font-family:'Inter', sans-serif;
    margin:0;
    padding:0;
    background:transparent;
    color:#F8FAFC;
}

* {
    font-family:'Inter', sans-serif;
    box-sizing:border-box;
}
.nora-operational-card {
    margin-bottom:10px;
    padding:18px 18px 18px 18px;

    border-radius:22px;
    border:1px solid rgba(37,150,190,0.14);

    background:
        radial-gradient(circle at top left, rgba(37,150,190,0.08) 0%, transparent 32%),
        linear-gradient(180deg, rgba(7,14,28,0.98) 0%, rgba(2,6,18,1) 100%);

    box-shadow:
        inset 0 1px 0 rgba(255,255,255,0.02),
        0 0 24px rgba(0,0,0,0.22);

    min-height: 340px;
    display:flex;
    flex-direction:column;
    justify-content:space-between;
}

.nora-operational-hero {
    display:flex;
    align-items:center;
    gap:24px;

    padding:22px 26px;
    border-radius:24px;

    border:1px solid rgba(37,150,190,0.16);

    background:
        radial-gradient(circle at top left, rgba(124,58,237,0.16) 0%, transparent 32%),
        linear-gradient(180deg, rgba(10,18,34,0.98) 0%, rgba(4,8,18,1) 100%);

    color:#F8FAFC;
    font-family:Inter,sans-serif;

    margin-bottom:14px;
}

.nora-operational-hero-icon {
    width:92px;
    min-width:92px;
    height:92px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:26px;

    background:linear-gradient(180deg, rgba(239,68,68,0.18) 0%, rgba(127,29,29,0.18) 100%);
    border:1px solid rgba(239,68,68,0.24);

    color:#EF4444;

    box-shadow:0 0 32px rgba(239,68,68,0.16);
}

.nora-operational-hero-content {
    flex:1;
}

.nora-operational-hero-title {
    font-size:26px;
    font-weight:900;
    line-height:1.2;
    margin-bottom:10px;
}

.nora-operational-hero-text {
    color:#CBD5E1;
    font-size:16px;
    line-height:1.6;
}

.nora-operational-label {
    color:#94A3B8;
    font-size:11px;
    font-weight:800;
    letter-spacing:0.8px;
    text-transform:uppercase;
    margin-bottom:6px;
}

.nora-operational-value {
    font-size:18px;
    font-weight:800;
    line-height:1.3;
    margin-bottom:0;
}

.nora-operational-subtext {
    color:#CBD5E1;
    font-size:13px;
    line-height:1.45;
    margin-top:6px;
}

.nora-operational-divider {
    height:1px;
    background:rgba(148,163,184,0.12);
    margin:14px 0 12px 0;
}

.nora-operational-grid {
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:10px;
    align-items:start;
}

.nora-operational-module {
    display:flex;
    align-items:flex-start;
    gap:20px;
    margin-top:8px;
    flex:1;
}

.nora-operational-zone-icon {
    width:56px;
    min-width:56px;
    height:56px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:16px;

    background:linear-gradient(180deg, rgba(37,150,190,0.16) 0%, rgba(37,150,190,0.08) 100%);
    border:1px solid rgba(37,150,190,0.22);

    font-size:24px;
}

.nora-operational-zone-main {
    flex:1;
    display:flex;
    align-items:flex-start;
    gap:28px;
}

.nora-operational-zone-top {
    display:flex;
    flex-direction:column;
    align-items:flex-start;
    justify-content:flex-start;
    gap:6px;
    min-width:170px;
    padding-top:4px;
}

.nora-operational-state-large {
    font-size:22px;
    font-weight:900;
    letter-spacing:0.4px;
    line-height:1;
}

.nora-operational-state-subtitle {
    font-size:13px;
    font-weight:600;
    color:#E2E8F0;
    line-height:1.2;
}

.nora-operational-guidance-panel {
    flex:1;
    padding-left:22px;
    border-left:1px solid rgba(148,163,184,0.18);
    min-height:120px;
    display:flex;
    align-items:flex-start;
}

.nora-notification-grid {
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:22px;
    margin-top:10px;
}

.nora-notification-module {
    display:flex;
    align-items:center;
    gap:22px;

    padding:18px 20px;
    border-radius:22px;

    border:1px solid rgba(37,150,190,0.14);

    background:
        radial-gradient(circle at top left, rgba(37,150,190,0.08) 0%, transparent 32%),
        linear-gradient(180deg, rgba(7,14,28,0.98) 0%, rgba(2,6,18,1) 100%);
}

.nora-notification-state {
    min-width:210px;
}

.nora-notification-title {
    font-size:18px;
    font-weight:800;
    color:#60A5FA;
    margin-bottom:6px;
}

.nora-notification-subtitle {
    font-size:15px;
    font-weight:500;
    color:#E2E8F0;
    line-height:1.4;
}

.nora-notification-divider {
    width:1px;
    align-self:stretch;
    background:rgba(148,163,184,0.16);
}


.nora-notification-text {
    flex:1;
    color:#E2E8F0;
    font-size:15px;
    line-height:1.7;
}

.nora-analyst-grid {
    display:grid;
    grid-template-columns:repeat(4, 1fr);
    gap:18px;
    margin-top:14px;
}

.nora-analyst-module {
    padding:18px;
    padding-bottom:24px;
    border-radius:22px;

    border:1px solid rgba(37,150,190,0.14);

    background:
        radial-gradient(circle at top left, rgba(37,150,190,0.08) 0%, transparent 32%),
        linear-gradient(180deg, rgba(7,14,28,0.98) 0%, rgba(2,6,18,1) 100%);

    min-height:220px;
}

.nora-analyst-header {
    display:flex;
    align-items:center;
    gap:14px;
    margin-bottom:18px;
}

.nora-analyst-title {
    font-size:17px;
    font-weight:800;
    color:#F8FAFC;
}

.nora-analyst-description {
    color:#CBD5E1;
    font-size:14px;
    line-height:1.6;
    margin-bottom:18px;
}


.nora-analyst-status {
    color:#60A5FA;
    font-size:13px;
    font-weight:700;
    margin-bottom:18px;
}

.nora-analyst-action-button {
    margin-top:8px;
    padding:14px 16px;

    border-radius:14px;
    border:1px solid rgba(37,150,190,0.18);

    background:linear-gradient(180deg, rgba(15,23,42,0.96) 0%, rgba(2,6,18,1) 100%);

    color:#F8FAFC;
    font-size:14px;
    font-weight:700;
    text-align:center;

    box-shadow:inset 0 1px 0 rgba(255,255,255,0.04);
}

.nora-operational-state {
    font-size:20px;
    font-weight:800;
    line-height:1.2;
    color:#F8FAFC;
}

.nora-operational-guidance {
    color:#CBD5E1;
    font-size:13px;
    line-height:1.65;
    padding-top:2px;
}

.nora-status-pill {
    padding:6px 12px;
    border-radius:999px;
    font-size:11px;
    font-weight:700;
}

.nora-status-pill.low {
    background:rgba(34,197,94,0.15);
    color:#22C55E;
}

.nora-status-pill.medium {
    background:rgba(245,158,11,0.15);
    color:#F59E0B;
}

.nora-status-pill.high {
    background:rgba(239,68,68,0.15);
    color:#EF4444;
}

.nora-status-pill.critical {
    background:rgba(239,68,68,0.22);
    color:#FCA5A5;
    border:1px solid rgba(239,68,68,0.28);
    box-shadow:0 0 14px rgba(239,68,68,0.14);
}

.nora-status-pill.investigating {
    background:rgba(245,158,11,0.16);
    color:#FCD34D;
}

.nora-status-pill.monitoring {
    background:rgba(34,197,94,0.16);
    color:#86EFAC;
}
</style>
"""

def render_operational_hero_card(overall_severity="HIGH"):

    components.html(
        f"""
        {CARD_STYLE}

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
            '● Coordinated malicious behaviour suspected<br>'
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
        {CARD_STYLE}
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
        {CARD_STYLE}
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
            'Passive Monitoring'
        ]
    )

    workflow_progress = (
        'Containment & Incident Response Active'
        if notification_summary['notification_priority'] == 'Critical'
        else 'Escalation Review & Threat Validation Active'
        if notification_summary['notification_priority'] == 'High'
        else 'Analyst Investigation & Correlation Active'
        if notification_summary['notification_priority'] == 'Medium'
        else 'Passive Monitoring Active'
    )

    workflow_status = (
        'CONTAINMENT ACTIVE'
        if notification_summary['notification_priority'] == 'Critical'
        else 'ESCALATED'
        if notification_summary['notification_priority'] == 'High'
        else 'INVESTIGATING'
        if notification_summary['notification_priority'] == 'Medium'
        else 'MONITORING'
    )

    active_stage_map = {
        'Critical': 'Containment',
        'High': 'Threat Validation',
        'Medium': 'Analyst Investigation',
        'Low': 'Passive Monitoring'
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
        <div style="display:flex; align-items:center; gap:8px;">

            <div style="
                padding:10px 14px;
                border-radius:14px;

                border:{
                    '1px solid rgba(96,165,250,0.42)'
                    if index == active_index
                    else '1px solid rgba(37,150,190,0.20)'
                    if index < active_index
                    else '1px solid rgba(148,163,184,0.08)'
                };

                background:{
                    'linear-gradient(180deg, rgba(59,130,246,0.24) 0%, rgba(37,99,235,0.18) 100%)'
                    if index == active_index
                    else 'linear-gradient(180deg, rgba(37,150,190,0.12) 0%, rgba(15,23,42,0.46) 100%)'
                    if index < active_index
                    else 'rgba(15,23,42,0.26)'
                };

                color:{
                    '#F8FAFC'
                    if index == active_index
                    else '#CBD5E1'
                    if index < active_index
                    else 'rgba(148,163,184,0.58)'
                };

                font-size:12px;
                font-weight:{'800' if index == active_index else '700'};
                min-width:148px;

                opacity:{
                    '1'
                    if index <= active_index
                    else '0.58'
                };

                box-shadow:{
                    '0 0 18px rgba(59,130,246,0.24)'
                    if index == active_index
                    else 'none'
                };
            ">

                <div style="
                    margin-bottom:6px;
                    white-space:nowrap;
                    display:flex;
                    align-items:center;
                    justify-content:space-between;
                    gap:10px;
                ">

                    <span>{step}</span>

                    {
                        '<span style="color:#7DD3FC; font-size:11px;">✔</span>'
                        if index < active_index
                        else '<span style="color:#60A5FA; font-size:11px;">●</span>'
                        if index == active_index
                        else ''
                    }

                </div>

                <div style="
                    font-size:10px;
                    letter-spacing:0.4px;
                    color:{
                        '#BFDBFE'
                        if index == active_index
                        else 'rgba(148,163,184,0.72)'
                    };
                    font-weight:700;
                ">
                    {workflow_timestamps[index]}
                </div>

            </div>

            {
                '<div style="color:rgba(96,165,250,0.22); font-size:14px;">→</div>'
                if step != workflow_steps[-1]
                else ''
            }

        </div>
        '''
        for index, step in enumerate(workflow_steps)
    ])

    components.html(
        f"""
        {CARD_STYLE}

        <div class='nora-operational-card'>

            <div class='nora-operational-label' style='margin-bottom:16px;'>
                Notification Workflow
            </div>

            <div style='display:flex; gap:14px; flex-wrap:wrap; margin-bottom:20px;'>

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

            <div style='
                display:flex;
                align-items:center;
                gap:10px;
                flex-wrap:wrap;
                margin-bottom:22px;
            '>
                {workflow_pipeline}
            </div>

            <div style='
                margin-bottom:18px;
                padding:14px 16px;
                border-radius:16px;
                border:1px solid rgba(37,150,190,0.14);
                background:rgba(15,23,42,0.42);
            '>

                <div class='nora-operational-label' style='margin-bottom:6px;'>
                    Workflow Progression
                </div>

                <div class='nora-operational-guidance'>
                    {workflow_progress}
                </div>

            </div>

            <div style='
                padding:18px;
                border-radius:18px;
                border:1px solid rgba(37,150,190,0.14);
                background:
                    radial-gradient(circle at top left, rgba(37,150,190,0.08) 0%, transparent 32%),
                    linear-gradient(180deg, rgba(7,14,28,0.98) 0%, rgba(2,6,18,1) 100%);
                margin-bottom:18px;
            '>

                <div class='nora-operational-label' style='margin-bottom:8px;'>
                    Operational Notification
                </div>

                <div class='nora-operational-guidance'>
                    {notification_summary['message']}
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
        height=500,
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
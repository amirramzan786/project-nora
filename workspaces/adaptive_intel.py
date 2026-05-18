

"""
Project N.O.R.A.
Adaptive Intelligence Workspace

Phase 3 Foundation:
Operational intelligence validation and inspection layer.

This workspace provides transparency into:
- enrichment intelligence
- behavioural scoring
- escalation orchestration
- notification workflows
- adaptive confidence modelling
"""

import pandas as pd
import streamlit as st

from components.ui_helpers import (
    render_section_title,
    render_workspace_header
)

from services.enrichment.ip_enrichment import enrich_ip
from services.scoring.pattern_similarity import analyse_pattern_similarity
from services.workflows.escalation_engine import generate_escalation_recommendation
from services.workflows.notification_engine import generate_notification_workflow


# =====================================================
# ADAPTIVE INTELLIGENCE WORKSPACE
# =====================================================


def render_adaptive_intelligence():
    """
    Render Adaptive Intelligence validation workspace.
    """

    render_workspace_header(
        "brain",
        "Adaptive Intelligence",
        "Operational intelligence validation, orchestration inspection and behavioural analysis workspace."
    )

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Test Threat Inputs
    # -------------------------------------------------

    render_section_title(
        "activity",
        "Threat Simulation Controls"
    )

    simulated_ip = st.text_input(
        "Test IP Address",
        value="185.220.101.1"
    )

    simulated_requests = st.slider(
        "Simulated Request Volume",
        min_value=50,
        max_value=5000,
        value=1400,
        step=50
    )

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Intelligence Pipeline Execution
    # -------------------------------------------------

    enriched_intel = enrich_ip(
        simulated_ip,
        simulated_requests
    )

    similarity = analyse_pattern_similarity(
        enriched_intel
    )

    escalation = generate_escalation_recommendation({
        **enriched_intel,
        "similarity_score": similarity["similarity_score"]
    })

    notification = generate_notification_workflow(
        escalation
    )

    # -------------------------------------------------
    # Intelligence Overview
    # -------------------------------------------------

    render_section_title(
        "shield_alert",
        "Intelligence Overview"
    )

    intelligence_overview = pd.DataFrame([
        {
            "Threat Level": enriched_intel["threat_level"],
            "Confidence": enriched_intel["confidence_score"],
            "Abuse Score": enriched_intel["abuse_score"],
            "Known Malicious": enriched_intel["known_malicious"],
            "Similarity": similarity["similarity_score"],
            "Escalation": escalation["escalation_level"],
            "Priority": escalation["response_priority"]
        }
    ])

    st.dataframe(
        intelligence_overview,
        use_container_width=True,
        hide_index=True
    )

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Enrichment Inspection
    # -------------------------------------------------

    render_section_title(
        "database",
        "Enrichment Intelligence"
    )

    st.json(enriched_intel)

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Behavioural Correlation
    # -------------------------------------------------

    render_section_title(
        "radar",
        "Behavioural Correlation"
    )

    st.json(similarity)

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Escalation Orchestration
    # -------------------------------------------------

    render_section_title(
        "triangle_alert",
        "Escalation Orchestration"
    )

    st.json(escalation)

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Notification Workflow
    # -------------------------------------------------

    render_section_title(
        "notifications",
        "Notification Workflow"
    )

    st.warning("NEW NOTIFICATION WORKFLOW RENDERER ACTIVE")
    workflow_channels = " • ".join(notification["channels"])

    workflow_steps = [
        "Threat Detected",
        "Escalation Triggered",
        "Notification Dispatch",
        "SOC Review",
        "Incident Queue"
    ]

    workflow_html = f"""
    <div class='nora-workspace-card'>

        <div style='display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px;'>

            <div class='nora-threat-stat'>
                <div class='nora-threat-stat-label'>Workflow Status</div>
                <div class='nora-threat-stat-value'>ACTIVE</div>
            </div>

            <div class='nora-threat-stat'>
                <div class='nora-threat-stat-label'>Priority</div>
                <div class='nora-threat-stat-value'>{notification['notification_priority']}</div>
            </div>

            <div class='nora-threat-stat'>
                <div class='nora-threat-stat-label'>SOC Notification</div>
                <div class='nora-threat-stat-value'>{'ENABLED' if notification['notify_soc'] else 'DISABLED'}</div>
            </div>

            <div class='nora-threat-stat'>
                <div class='nora-threat-stat-label'>Acknowledgement</div>
                <div class='nora-threat-stat-value'>{'REQUIRED' if notification['requires_acknowledgement'] else 'OPTIONAL'}</div>
            </div>

        </div>

        <div style='display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; margin-bottom:28px;'>
            {
                ''.join([
                    f'''<div style="display:flex; align-items:center; gap:10px;">
                            <div style="padding:10px 16px; border:1px solid rgba(0,255,255,0.15); border-radius:10px; background:rgba(0,255,255,0.03); font-size:0.82rem; color:#d8f8ff; white-space:nowrap;">
                                {step}
                            </div>
                            {'<div style="color:rgba(120,220,255,0.5); font-size:1rem;">→</div>' if step != workflow_steps[-1] else ''}
                        </div>'''
                    for step in workflow_steps
                ])
            }
        </div>

        <div style='margin-bottom:22px;'>
            <div style='font-size:0.78rem; text-transform:uppercase; letter-spacing:1px; color:rgba(140,220,255,0.7); margin-bottom:8px;'>Operational Notification</div>
            <div style='padding:16px; border-radius:12px; border:1px solid rgba(0,255,255,0.12); background:rgba(0,255,255,0.03); color:#dff9ff; line-height:1.6;'>
                {notification['message']}
            </div>
        </div>

        <div style='display:grid; grid-template-columns:1fr 1fr; gap:18px;'>

            <div style='padding:18px; border-radius:12px; border:1px solid rgba(0,255,255,0.12); background:rgba(0,255,255,0.025);'>
                <div style='font-size:0.78rem; text-transform:uppercase; letter-spacing:1px; color:rgba(140,220,255,0.7); margin-bottom:10px;'>Notification Channels</div>
                <div style='color:#dff9ff; line-height:1.7;'>
                    {workflow_channels}
                </div>
            </div>

            <div style='padding:18px; border-radius:12px; border:1px solid rgba(0,255,255,0.12); background:rgba(0,255,255,0.025);'>
                <div style='font-size:0.78rem; text-transform:uppercase; letter-spacing:1px; color:rgba(140,220,255,0.7); margin-bottom:10px;'>Recommended Analyst Action</div>
                <div style='color:#dff9ff; line-height:1.7;'>
                    {notification['recommended_action']}
                </div>
            </div>

        </div>

    </div>
    """

    st.markdown(
        workflow_html,
        unsafe_allow_html=True
    )

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    st.caption(
        "Adaptive Intelligence provides operational transparency into the Phase 3 orchestration pipeline including enrichment, behavioural scoring, escalation reasoning and notification workflow generation before future ML-assisted automation layers are introduced."
    )
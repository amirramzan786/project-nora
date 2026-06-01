import streamlit as st

from components.operational_cards import render_notification_workflow_card
from services.workflows.escalation_engine import generate_escalation_recommendation
from services.workflows.notification_engine import generate_notification_workflow


def render_notification_workflow_panel(enriched_threats):
    with st.container(border=True):
        if enriched_threats:
            highest_threat = max(
                enriched_threats,
                key=lambda threat: threat.get("confidence_score", 0)
            )

            escalation_summary = generate_escalation_recommendation(
                highest_threat
            )

            notification_summary = generate_notification_workflow(
                escalation_summary
            )

            render_notification_workflow_card(
                notification_summary
            )

        else:
            st.info("No threat source telemetry available.")
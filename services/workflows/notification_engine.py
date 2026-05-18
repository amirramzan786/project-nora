"""
Project N.O.R.A.
Operational Notification Engine

Phase 3 Foundation:
Operational communication orchestration layer.

This service transforms escalation recommendations
into structured notification workflows for:
- SOC alerting
- Email escalation
- Twilio integration
- Webhook dispatch
- Future Teams/Slack integrations
"""


# =====================================================
# NOTIFICATION ENGINE
# =====================================================


def generate_notification_workflow(escalation_data):
    """
    Generate structured operational notification workflows
    from escalation intelligence.
    """

    escalation_level = escalation_data.get(
        "escalation_level",
        "Low"
    )

    response_priority = escalation_data.get(
        "response_priority",
        "P4"
    )

    recommended_action = escalation_data.get(
        "recommended_action",
        "No action required."
    )

    analyst_guidance = escalation_data.get(
        "analyst_guidance",
        "Operationally stable."
    )

    # -------------------------------------------------
    # Phase 2.5 Operational Workflow Progression
    # -------------------------------------------------

    workflow_stages = {
        "Critical": [
            "Detection",
            "Threat Validation",
            "SOC Escalation",
            "Containment",
            "Incident Response"
        ],
        "High": [
            "Detection",
            "Correlation",
            "Threat Validation",
            "Escalation Review"
        ],
        "Medium": [
            "Detection",
            "Behaviour Analysis",
            "Analyst Investigation"
        ],
        "Low": [
            "Detection",
            "Passive Monitoring"
        ]
    }

    # -------------------------------------------------
    # Critical Notification Workflow
    # -------------------------------------------------

    if escalation_level == "Critical":

        return {
            "notify_soc": True,
            "notification_priority": "Critical",
            "channels": [
                "SOC Dashboard",
                "Email",
                "Twilio",
                "Incident Response Bridge"
            ],
            "requires_acknowledgement": True,
            "message": (
                f"CRITICAL INCIDENT DETECTED | "
                f"Priority: {response_priority} | "
                f"SOC escalation workflow activated. "
                f"Immediate containment and analyst coordination required."
            ),
            "recommended_action": recommended_action,
            "analyst_guidance": analyst_guidance,
            "workflow_stages": workflow_stages.get(
                escalation_level,
                workflow_stages["Low"]
            )
        }

    # -------------------------------------------------
    # High Notification Workflow
    # -------------------------------------------------

    if escalation_level in ["High", "Critical"]:

        return {
            "notify_soc": True,
            "notification_priority": "High",
            "channels": [
                "SOC Dashboard",
                "Email"
            ],
            "requires_acknowledgement": True,
            "message": (
                f"Elevated coordinated threat activity detected | "
                f"Priority: {response_priority} | "
                f"Threat validation and escalation review initiated."
            ),
            "recommended_action": recommended_action,
            "analyst_guidance": analyst_guidance,
            "workflow_stages": workflow_stages.get(
                escalation_level,
                workflow_stages["Low"]
            )
        }

    # -------------------------------------------------
    # Medium Notification Workflow
    # -------------------------------------------------

    if escalation_level == "Medium":

        return {
            "notify_soc": False,
            "notification_priority": "Medium",
            "channels": [],
            "requires_acknowledgement": False,
            "message": (
                "Elevated behavioural anomalies detected. "
                "Analyst investigation and telemetry correlation remain active."
            ),
            "recommended_action": recommended_action,
            "analyst_guidance": analyst_guidance,
            "workflow_stages": workflow_stages.get(
                escalation_level,
                workflow_stages["Low"]
            )
        }

    # -------------------------------------------------
    # Low Notification Workflow
    # -------------------------------------------------

    return {
        "notify_soc": False,
        "notification_priority": "Low",
        "channels": [],
        "requires_acknowledgement": False,
        "message": (
            "Baseline traffic conditions remain operationally stable."
        ),
        "recommended_action": recommended_action,
        "analyst_guidance": analyst_guidance,
        "workflow_stages": workflow_stages.get(
            escalation_level,
            workflow_stages["Low"]
        )
    }
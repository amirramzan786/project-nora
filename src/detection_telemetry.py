def get_telemetry_profile(overall_severity):
    return {
        "LOW": {
            "queue_state": "Monitoring Queue",
            "workflow_state": "Passive Monitoring",
            "distribution": {
                "low": 0.78,
                "medium": 0.18,
                "high": 0.04
            },
            "timeline_state": "Monitoring Active",
            "correlation_state": "Distributed Probe Behaviour",
            "confidence_modifier": -8,
            "escalation_modifier": -1
        },
        "MEDIUM": {
            "queue_state": "Analyst Review Queue",
            "workflow_state": "Investigation Active",
            "distribution": {
                "low": 0.32,
                "medium": 0.53,
                "high": 0.15
            },
            "timeline_state": "Investigation Active",
            "correlation_state": "Coordinated Burst Pattern",
            "confidence_modifier": 0,
            "escalation_modifier": 1
        },
        "HIGH": {
            "queue_state": "Priority Escalation Queue",
            "workflow_state": "Escalation Active",
            "distribution": {
                "low": 0.14,
                "medium": 0.33,
                "high": 0.53
            },
            "timeline_state": "Escalation Active",
            "correlation_state": "Sustained Coordinated Activity",
            "confidence_modifier": 7,
            "escalation_modifier": 3
        }
    }.get(overall_severity)
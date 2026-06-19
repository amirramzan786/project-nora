import streamlit as st

from components.ui_helpers import (
    render_section_title,
    render_workspace_header
)

from src.icons import get_icon

from services.enrichment.ip_enrichment import enrich_ip

from services.scoring.pattern_similarity import analyse_pattern_similarity
from services.intelligence.detection_history import (
    build_behavioural_memory_repository,
    build_detection_intelligence_summary,
    build_learning_trend_summary,
    compare_with_detection_history,
    calculate_adaptive_confidence_adjustment,
)


# =====================================================
# ADAPTIVE INTELLIGENCE WORKSPACE
# =====================================================


def render_adaptive_intelligence(
    ip_totals,
    alerts,
    anomalies,
    time_counts,
    dataset_mode=None,
    dataset_name=None,
    on_reset_dataset=None,
):
    """
    Render Adaptive Intelligence validation workspace.
    """

    render_workspace_header(
        "brain",
        "Adaptive Intelligence",
        "Behavioural learning, memory correlation and adaptive confidence reinforcement workspace.",
        dataset_mode=dataset_mode,
        dataset_name=dataset_name,
        on_reset_dataset=on_reset_dataset,
        reset_key="reset_dataset_adaptive_intelligence",
    )

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Adaptive Learning Inputs (removed simulation controls)
    # -------------------------------------------------

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Intelligence Pipeline Execution
    # -------------------------------------------------

    total_requests = int(sum(ip_totals.values())) if ip_totals else 0

    top_ip = (
        max(ip_totals, key=ip_totals.get)
        if ip_totals
        else "Unknown"
    )

    top_ip_requests = (
        ip_totals.get(top_ip, 0)
        if ip_totals
        else 0
    )

    source_concentration = (
        round(top_ip_requests / total_requests, 2)
        if total_requests > 0
        else 0
    )

    anomaly_count = len(anomalies) if anomalies is not None else 0

    anomaly_ratio = (
        round(anomaly_count / total_requests, 2)
        if total_requests > 0
        else 0
    )

    enriched_intel = enrich_ip(
        top_ip,
        top_ip_requests
    )

    enriched_intel.update({
        "total_requests": total_requests,
        "request_volume": total_requests,
        "anomaly_count": anomaly_count,
        "anomaly_ratio": anomaly_ratio,
        "source_concentration": source_concentration,
    })

    similarity = analyse_pattern_similarity(
        enriched_intel
    )

    memory_repository = build_behavioural_memory_repository()
    detection_intelligence_summary = build_detection_intelligence_summary()
    learning_trend_summary = build_learning_trend_summary()

    memory_rows_html = ""

    for memory_item in memory_repository:
        strength = int(memory_item.get("memory_strength", 0))

        memory_rows_html += f"""
        <div class='nora-adaptive-memory-row'>
            <span>{memory_item.get('pattern', 'Unknown')}</span>
            <div class='nora-adaptive-memory-bar'>
                <span style='width:{strength}%;'></span>
            </div>
            <strong>{strength}%</strong>
        </div>
        """

    if not memory_rows_html:
        memory_rows_html = """
        <div class='nora-adaptive-panel-content'>
            No behavioural memory has been stored yet.
        </div>
        """

    enrichment_impact = min(
        12,
        round(enriched_intel.get("abuse_score", 0) / 10)
    )

    base_confidence = max(
        0,
        enriched_intel.get("confidence_score", 0) - enrichment_impact
    )

    adaptive_session_data = {
        "total_requests": total_requests,
        "peak_requests": top_ip_requests,
        "average_requests": round(total_requests / max(len(ip_totals), 1), 2) if ip_totals else 0,
        "anomaly_count": anomaly_count,
        "anomaly_ratio": anomaly_ratio,
        "source_concentration": source_concentration,
        "traffic_pattern": similarity.get("matched_pattern", "Unknown Behaviour"),
        "severity": enriched_intel.get("threat_level", "Unknown"),
        "confidence": base_confidence,
        "matched_pattern": similarity.get("matched_pattern", "Unknown Behaviour"),
        "similarity_score": similarity.get("similarity_score", 0),
        "primary_source": top_ip,
    }

    historical_adaptive_matches = compare_with_detection_history(
        adaptive_session_data,
        history_limit=100,
        top_n=3,
    )

    adaptive_confidence_result = calculate_adaptive_confidence_adjustment(
        historical_adaptive_matches,
        base_confidence,
    )

    memory_reinforcement = adaptive_confidence_result["reinforcement_score"]

    adjusted_confidence = min(
        100,
        adaptive_confidence_result["adjusted_confidence"] + enrichment_impact
    )

    # -------------------------------------------------
    # Learning Pipeline
    # -------------------------------------------------

    render_section_title(
        "brain",
        "N.O.R.A Learning Pipeline"
    )

    learning_pipeline_html = f"""
    <div class='nora-adaptive-card'>
        <div class='nora-adaptive-pipeline'>

            <div class='nora-adaptive-stage blue'>
                <div class='nora-adaptive-stage-number'>1</div>
                <div class='nora-adaptive-stage-title'>Observed Activity</div>
                <div class='nora-adaptive-stage-copy'>Traffic profile captured and analysed</div>
            </div>

            <div class='nora-adaptive-stage-arrow'>→</div>

            <div class='nora-adaptive-stage cyan'>
                <div class='nora-adaptive-stage-number'>2</div>
                <div class='nora-adaptive-stage-title'>Behavioural Correlation</div>
                <div class='nora-adaptive-stage-copy'>Compared against historical memory</div>
            </div>

            <div class='nora-adaptive-stage-arrow'>→</div>

            <div class='nora-adaptive-stage purple'>
                <div class='nora-adaptive-stage-number'>3</div>
                <div class='nora-adaptive-stage-title'>Confidence Reinforcement</div>
                <div class='nora-adaptive-stage-copy'>Confidence adjusted using memory evidence</div>
            </div>

            <div class='nora-adaptive-stage-arrow'>→</div>

            <div class='nora-adaptive-stage amber'>
                <div class='nora-adaptive-stage-number'>4</div>
                <div class='nora-adaptive-stage-title'>Learning Outcome</div>
                <div class='nora-adaptive-stage-copy'>Pattern stored for future comparison</div>
            </div>

            <div class='nora-adaptive-stage-arrow'>→</div>

            <div class='nora-adaptive-stage green'>
                <div class='nora-adaptive-stage-number'>5</div>
                <div class='nora-adaptive-stage-title'>Future Impact</div>
                <div class='nora-adaptive-stage-copy'>Future detections become stronger</div>
            </div>

        </div>
    </div>
    """

    st.html(learning_pipeline_html)

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

    enrichment_html = f"""
    <div class='nora-adaptive-card'>

        <div class='nora-adaptive-grid'>

            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Source IP</div>
                <div class='nora-adaptive-metric-value'>{enriched_intel.get('ip_address', 'N/A')}</div>
            </div>

            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Activity Profile</div>
                <div class='nora-adaptive-metric-value'>{enriched_intel.get('activity_profile', 'Unknown')}</div>
            </div>

            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Regional Risk</div>
                <div class='nora-adaptive-metric-value'>{enriched_intel.get('regional_risk', 'N/A')}</div>
            </div>

            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Abuse Score</div>
                <div class='nora-adaptive-metric-value'>{enriched_intel.get('abuse_score', 0)}</div>
            </div>

        </div>

        <div class='nora-adaptive-insight-panel'>
            <div class='nora-adaptive-panel-title'>Enrichment Assessment</div>
            <div class='nora-adaptive-panel-content'>
                N.O.R.A assessed the observed activity using behavioural indicators, detection evidence and historical memory. This context becomes evidence for behavioural memory comparison and adaptive confidence reinforcement.
            </div>
        </div>

    </div>
    """

    st.html(enrichment_html)

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Behavioural Correlation
    # -------------------------------------------------

    st.html(
        f"""
        <div class='nora-section-title'>
            {get_icon("activity")}
            <span>Behavioural Memory Centre</span>
        </div>
        """
    )

    behavioural_memory_html = f"""
    <div class='nora-adaptive-card'>

        <div class='nora-adaptive-insight-panel' style='margin-top:0; margin-bottom:18px;'>
            <div class='nora-adaptive-panel-title'>Behavioural Memory Assessment</div>
            <div class='nora-adaptive-panel-content'>
                N.O.R.A compared the current activity profile against previously observed behavioural patterns and generated a similarity score of {similarity.get('similarity_score', 0)}%. This memory match can reinforce future confidence scoring and improve repeat-pattern classification.
            </div>
        </div>

        <div style='display:grid; grid-template-columns: 0.85fr 1.15fr; gap:18px;'>

            <div class='nora-adaptive-insight-panel' style='margin-top:0;'>
                <div class='nora-adaptive-panel-title'>Current Behaviour Match</div>

                <div style='display:grid; grid-template-columns:2fr 1fr 1fr 1fr; gap:12px; margin-top:12px;'>

                    <div class='nora-adaptive-metric'>
                        <div class='nora-adaptive-metric-label'>Pattern</div>
                        <div class='nora-adaptive-metric-value'>{similarity.get('matched_pattern', 'Unknown')}</div>
                    </div>

                    <div class='nora-adaptive-metric'>
                        <div class='nora-adaptive-metric-label'>Similarity</div>
                        <div class='nora-adaptive-metric-value'>{similarity.get('similarity_score', 0)}%</div>
                    </div>

                    <div class='nora-adaptive-metric'>
                        <div class='nora-adaptive-metric-label'>Strength</div>
                        <div class='nora-adaptive-metric-value'>{similarity.get('correlation_strength', 'N/A')}</div>
                    </div>

                    <div class='nora-adaptive-metric'>
                        <div class='nora-adaptive-metric-label'>Status</div>
                        <div class='nora-adaptive-metric-value'>MEMORISED</div>
                    </div>

                </div>
            </div>

            <div class='nora-adaptive-learning-panel' style='margin-top:0;'>
                <div class='nora-adaptive-panel-title'>Behavioural Memory Repository</div>
                {memory_rows_html}
                <div class='nora-adaptive-panel-content' style='margin-top:18px;'>
                    Historical behavioural memory allows N.O.R.A to compare the current activity profile against previously observed DDoS-style patterns and identify reusable detection evidence.
                </div>
            </div>

        </div>

    </div>
    """

    st.html(behavioural_memory_html)

    historical_detection_html = f"""
    <div class='nora-adaptive-card' style='margin-top:18px;'>
        <div class='nora-adaptive-panel-title'>Historical Detection Intelligence</div>

        <div class='nora-adaptive-grid' style='margin-top:14px;'>
            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Stored Detections</div>
                <div class='nora-adaptive-metric-value'>{detection_intelligence_summary.get('total_detections', 0)}</div>
            </div>

            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Avg Adaptive Confidence</div>
                <div class='nora-adaptive-metric-value'>{detection_intelligence_summary.get('average_adaptive_confidence', 0)}%</div>
            </div>

            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Avg Reinforcement</div>
                <div class='nora-adaptive-metric-value'>+{detection_intelligence_summary.get('average_reinforcement', 0)}</div>
            </div>

            <div class='nora-adaptive-metric'>
                <div class='nora-adaptive-metric-label'>Validated Sessions</div>
                <div class='nora-adaptive-metric-value'>{detection_intelligence_summary.get('validated_sessions', 0)}</div>
            </div>
        </div>

        <div class='nora-adaptive-insight-panel' style='margin-top:18px;'>
            <div class='nora-adaptive-panel-title'>Historical Classification Breakdown</div>

            <div class='nora-adaptive-panel-content'>
                {
                    '<br>'.join(
                        [
                            f"{classification}: {count} detections"
                            for classification, count in detection_intelligence_summary.get(
                                'classification_distribution', {}
                            ).items()
                        ]
                    )
                    or 'No historical classifications recorded yet.'
                }
            </div>
        </div>

        <div class='nora-adaptive-insight-panel' style='margin-top:18px;'>
            <div class='nora-adaptive-panel-title'>Behavioural Learning Trend</div>

            <div class='nora-adaptive-grid' style='margin-top:12px;'>
                <div class='nora-adaptive-metric'>
                    <div class='nora-adaptive-metric-label'>Trend</div>
                    <div class='nora-adaptive-metric-value'>{learning_trend_summary.get('trend', 'Unknown')}</div>
                </div>

                <div class='nora-adaptive-metric'>
                    <div class='nora-adaptive-metric-label'>Current Average</div>
                    <div class='nora-adaptive-metric-value'>{learning_trend_summary.get('current_average', 0)}</div>
                </div>

                <div class='nora-adaptive-metric'>
                    <div class='nora-adaptive-metric-label'>Previous Average</div>
                    <div class='nora-adaptive-metric-value'>{learning_trend_summary.get('previous_average', 0)}</div>
                </div>

                <div class='nora-adaptive-metric'>
                    <div class='nora-adaptive-metric-label'>Change</div>
                    <div class='nora-adaptive-metric-value'>{learning_trend_summary.get('change_percent', 0)}%</div>
                </div>
            </div>

            <div class='nora-adaptive-panel-content' style='margin-top:12px;'>
                {learning_trend_summary.get('trend_summary', '')}
            </div>
        </div>

        <div class='nora-adaptive-insight-panel' style='margin-top:18px;'>
            <div class='nora-adaptive-panel-title'>Memory Learning Summary</div>
            <div class='nora-adaptive-panel-content'>
                N.O.R.A has most frequently observed <strong>{detection_intelligence_summary.get('most_common_classification', 'Unknown')}</strong> behaviour, with <strong>{detection_intelligence_summary.get('most_common_pattern', 'Unknown')}</strong> appearing as the strongest recurring memory pattern. The most recent stored detection was recorded at {detection_intelligence_summary.get('last_detection_seen', 'Unknown')}.
            </div>
        </div>
    </div>
    """

    st.html(historical_detection_html)

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Adaptive Confidence Engine
    # -------------------------------------------------

    render_section_title(
        "brain",
        "Adaptive Confidence Assessment"
    )

    confidence_assessment_html = f"""
    <div class='nora-adaptive-card'>

        <div class='nora-adaptive-confidence-flow'>

            <div class='nora-adaptive-confidence-step'>
                <div class='nora-adaptive-metric-label'>Base Confidence</div>
                <div class='nora-adaptive-confidence-value'>{base_confidence}%</div>
                <div class='nora-adaptive-confidence-copy'>Initial confidence from enrichment and detection evidence</div>
            </div>

            <div class='nora-adaptive-confidence-operator'>+</div>

            <div class='nora-adaptive-confidence-step'>
                <div class='nora-adaptive-metric-label'>Memory Reinforcement</div>
                <div class='nora-adaptive-confidence-value'>+{memory_reinforcement}%</div>
                <div class='nora-adaptive-confidence-copy'>Historical detection memory strengthens confidence weighting</div>
            </div>

            <div class='nora-adaptive-confidence-operator'>+</div>

            <div class='nora-adaptive-confidence-step'>
                <div class='nora-adaptive-metric-label'>Behavioural Evidence Impact</div>
                <div class='nora-adaptive-confidence-value'>+{enrichment_impact}%</div>
                <div class='nora-adaptive-confidence-copy'>Behavioural evidence supports assessment</div>
            </div>

            <div class='nora-adaptive-confidence-operator'>=</div>

            <div class='nora-adaptive-confidence-step final'>
                <div class='nora-adaptive-metric-label'>Adjusted Confidence</div>
                <div class='nora-adaptive-confidence-value'>{adjusted_confidence}%</div>
                <div class='nora-adaptive-confidence-copy'>Final adaptive confidence after memory reinforcement</div>
            </div>

        </div>

        <div class='nora-adaptive-confidence-panel'>
            <div class='nora-adaptive-panel-title'>Confidence Reinforcement Reasoning</div>
            <div class='nora-adaptive-panel-content'>
                N.O.R.A compared the current activity profile against saved detection history and applied a real historical reinforcement score of +{memory_reinforcement}%. Behavioural evidence contributed +{enrichment_impact}%, producing an adjusted confidence score of {adjusted_confidence}%.
            </div>
        </div>

    </div>
    """

    st.html(confidence_assessment_html)

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    # -------------------------------------------------
    # Learning Outcome
    # -------------------------------------------------

    st.html(
        f"""
        <div class='nora-section-title'>
            {get_icon('activity')}
            <span>Adaptive Learning Outcome</span>
        </div>
        """
    )

    learning_outcome_html = f"""
    <div class='nora-adaptive-card nora-adaptive-outcome-card'>
        <div class='nora-adaptive-outcome-icon'>✓</div>
        <div>
            <div class='nora-adaptive-panel-title'>LEARNING STORED</div>
            <div class='nora-adaptive-panel-content'>
                Pattern memory has been reinforced. Future detections with similar behavioural characteristics can receive stronger confidence weighting and faster similarity classification.
            </div>
            <div class='nora-adaptive-outcome-list'>
                <span>Pattern reinforced in memory</span>
                <span>Confidence model improved</span>
                <span>Future detections strengthened</span>
            </div>
        </div>
    </div>
    """

    st.html(learning_outcome_html)

    st.markdown(
        "<div class='nora-workspace-spacing'></div>",
        unsafe_allow_html=True
    )

    st.caption(
        "Adaptive Intelligence demonstrates how N.O.R.A uses behavioural memory, detection evidence and confidence reinforcement to make future detections stronger."
    )
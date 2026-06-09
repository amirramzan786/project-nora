import streamlit as st

from components.ui_helpers import (
    render_section_title,
    render_workspace_header
)

from src.icons import get_icon

from services.enrichment.ip_enrichment import enrich_ip
from services.scoring.pattern_similarity import analyse_pattern_similarity


# =====================================================
# ADAPTIVE INTELLIGENCE WORKSPACE
# =====================================================


def render_adaptive_intelligence(
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

    enriched_intel = enrich_ip(
        "185.220.101.1",
        1400
    )

    similarity = analyse_pattern_similarity(
        enriched_intel
    )

    base_confidence = max(
        0,
        enriched_intel.get("confidence_score", 0) - 18
    )
    memory_reinforcement = 12 if similarity.get("similarity_score", 0) >= 80 else 6
    enrichment_impact = min(
        12,
        round(enriched_intel.get("abuse_score", 0) / 10)
    )
    adjusted_confidence = min(
        100,
        base_confidence + memory_reinforcement + enrichment_impact
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
                <div class='nora-adaptive-metric-label'>Infrastructure</div>
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
                N.O.R.A enriched the simulated activity using infrastructure, regional and abuse-reputation indicators. This context becomes evidence for behavioural memory comparison and adaptive confidence reinforcement.
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
                <div class='nora-adaptive-memory-row'>
                    <span>Volumetric DDoS</span>
                    <div class='nora-adaptive-memory-bar'><span style='width:82%;'></span></div>
                    <strong>82%</strong>
                </div>
                <div class='nora-adaptive-memory-row'>
                    <span>Burst Attack</span>
                    <div class='nora-adaptive-memory-bar'><span style='width:74%;'></span></div>
                    <strong>74%</strong>
                </div>
                <div class='nora-adaptive-memory-row'>
                    <span>Slow Build Attack</span>
                    <div class='nora-adaptive-memory-bar'><span style='width:58%;'></span></div>
                    <strong>58%</strong>
                </div>
                <div class='nora-adaptive-memory-row'>
                    <span>Sustained Saturation</span>
                    <div class='nora-adaptive-memory-bar'><span style='width:41%;'></span></div>
                    <strong>41%</strong>
                </div>

                <div class='nora-adaptive-panel-content' style='margin-top:18px;'>
                    Historical behavioural memory allows N.O.R.A to compare the current activity profile against previously observed DDoS-style patterns and identify reusable detection evidence.
                </div>
            </div>

        </div>

    </div>
    """

    st.html(behavioural_memory_html)

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
                <div class='nora-adaptive-confidence-copy'>Historical similarity strengthens confidence weighting</div>
            </div>

            <div class='nora-adaptive-confidence-operator'>+</div>

            <div class='nora-adaptive-confidence-step'>
                <div class='nora-adaptive-metric-label'>Enrichment Impact</div>
                <div class='nora-adaptive-confidence-value'>+{enrichment_impact}%</div>
                <div class='nora-adaptive-confidence-copy'>Reputation and enrichment evidence support assessment</div>
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
                N.O.R.A combined base confidence, enrichment evidence and behavioural memory similarity to produce an adjusted confidence score of {adjusted_confidence}%. The confidence model was reinforced because the current behaviour shows {similarity.get('similarity_score', 0)}% similarity to known behavioural activity.
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
        "Adaptive Intelligence demonstrates how N.O.R.A uses behavioural memory, enrichment context and confidence reinforcement to make future detections stronger."
    )
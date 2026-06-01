import streamlit as st

from src.icons import get_icon
from components.ui_helpers import render_section_title
from services.scoring.pattern_similarity import analyse_pattern_similarity


def render_correlated_threat_summary(
    enriched_threats,
    estimated_confidence
):
    if not enriched_threats:
        return

    primary_threat = enriched_threats[0]
    primary_similarity = analyse_pattern_similarity(primary_threat)

    intelligence_summary = primary_similarity.get(
        "behavioural_summary",
        "No behavioural intelligence available."
    )

    correlation_strength = primary_similarity.get(
        "correlation_strength",
        "Low"
    )

    matched_pattern = primary_similarity.get(
        "matched_pattern",
        "Unknown Behaviour"
    )

    justification_points = primary_threat.get(
        "confidence_justification",
        []
    )

    correlation_points = primary_similarity.get(
        "correlation_indicators",
        []
    )

    st.markdown(
        "<div class='nora-workspace-spacing-sm'></div>",
        unsafe_allow_html=True
    )

    with st.container(border=True):

        render_section_title(
            'link',
            'Correlated Threat Intelligence Summary'
        )

        metric_col1, metric_col2, metric_col3, metric_col4, metric_col5 = st.columns([0.9, 0.9, 1.1, 0.9, 0.9])

        with metric_col1:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('shield')}</span>
                        <span class='nora-intelligence-card-label'>Detection</span>
                    </div>
                    <div class='nora-intelligence-meta-value'>
                        {matched_pattern}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with metric_col2:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('activity')}</span>
                        <span class='nora-intelligence-card-label'>Correlation</span>
                    </div>
                    <div class='nora-intelligence-meta-value'>
                        {correlation_strength}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with metric_col3:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('brain')}</span>
                        <span class='nora-intelligence-card-label'>Assessment</span>
                    </div>
                    <div class='nora-intelligence-meta-value'>
                        {intelligence_summary}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with metric_col4:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact nora-intelligence-metric-card'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('target')}</span>
                        <span class='nora-intelligence-card-label'>Pattern Similarity</span>
                    </div>
                    <div class='nora-intelligence-metric-value nora-intelligence-metric-value-similarity'>
                        {primary_similarity.get('similarity_score', 0)}%
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with metric_col5:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact nora-intelligence-metric-card'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('shield')}</span>
                        <span class='nora-intelligence-card-label'>Confidence</span>
                    </div>
                    <div class='nora-intelligence-metric-value nora-intelligence-metric-value-confidence'>
                        {estimated_confidence}%
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown(
            "<div class='nora-workspace-spacing-xs'></div>",
            unsafe_allow_html=True
        )

        info_row_1_col1, info_row_1_col2 = st.columns([1, 1])

        with info_row_1_col1:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('server')}</span>
                        <span class='nora-intelligence-card-label'>Infrastructure</span>
                    </div>
                    <div class='nora-intelligence-meta-value'>
                        {primary_threat.get('threat_infrastructure', 'Unknown')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with info_row_1_col2:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('globe')}</span>
                        <span class='nora-intelligence-card-label'>Region Cluster</span>
                    </div>
                    <div class='nora-intelligence-meta-value'>
                        {primary_threat.get('region_cluster', 'Unknown')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown(
            "<div class='nora-workspace-spacing-sm'></div>",
            unsafe_allow_html=True
        )

        info_row_2_col1, info_row_2_col2 = st.columns([1, 1])

        with info_row_2_col1:
            indicator_badges = "".join([
                f"<span class='nora-intelligence-indicator-badge'>{indicator}</span>"
                for indicator in correlation_points[:3]
            ]) if correlation_points else "No indicators"

            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact nora-intelligence-meta-card-indicators'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('link')}</span>
                        <span class='nora-intelligence-card-label'>Correlation Indicators</span>
                    </div>
                    <div class='nora-intelligence-meta-value'>
                        {indicator_badges}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with info_row_2_col2:
            st.markdown(
                f"""
                <div class='nora-intelligence-meta-card nora-intelligence-meta-card-compact'>
                    <div class='nora-intelligence-card-header'>
                        <span class='nora-intelligence-card-icon'>{get_icon('clipboard')}</span>
                        <span class='nora-intelligence-card-label'>Confidence Justification</span>
                    </div>
                    <div class='nora-intelligence-meta-value'>
                        {', '.join(justification_points[:2]) if justification_points else 'No justification'}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown(
                "<div class='nora-workspace-spacing-xs'></div>",
                unsafe_allow_html=True
            )
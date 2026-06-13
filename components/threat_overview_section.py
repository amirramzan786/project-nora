

import textwrap

import streamlit as st


def render_html(html: str) -> None:
    """Render raw HTML directly without Markdown parsing."""
    st.html(textwrap.dedent(html).strip())



def render_threat_overview_section(
    intelligence_panels,
    reputation_card_value,
    reputation_card_meta,
    asn_value,
    asn_provider,
    geo_country,
    geo_city,
    geographic_card_meta,
    intelligence_coverage,
    coverage_card_meta,
    top_ip,
    threat_classification,
    enriched_infrastructure_class,
    threat_rating,
    confidence_bars,
    assessment_confidence_pct,
    severity_badge,
    infrastructure_confidence,
    behavioural_risk,
    coverage_indicator,
    assessment_summary,
    infrastructure_assessment,
    behavioural_profile,
    coordination_level,
    consistency_level,
    persistence_level,
):
    """Render the top Threat Intelligence telemetry and overview section."""

    drawer_panels_html = ""

    for panel_key, panel_data in intelligence_panels.items():
        panel_id = panel_key.lower()
        panel_rows_html = ""

        for label, value in panel_data.get("rows", []):
            panel_rows_html += f"""
            <div class='nora-threat-panel-row'>
                <div class='nora-threat-panel-label'>{label}</div>
                <div class='nora-threat-panel-value'>{value}</div>
            </div>
            """

        drawer_panels_html += f"""
        <div class='nora-threat-css-drawer nora-threat-css-drawer-{panel_id}'>
            <div class='nora-threat-panel-header'>
                <div>
                    <div class='nora-threat-panel-kicker'>SOURCE CONTEXT</div>
                    <div class='nora-threat-panel-title'>{panel_data.get("title")}</div>
                </div>
                <div class='nora-threat-panel-status'>ACTIVE</div>
                <label class='nora-threat-panel-close' for='nora-panel-none'>×</label>
            </div>
            <div class='nora-threat-panel-summary'>{panel_data.get("summary")}</div>
            <div class='nora-threat-panel-grid'>
                {panel_rows_html}
            </div>
        </div>
        """

    geographic_region = (
        geo_country
        if geo_city == 'Unknown'
        else f'{geo_city}, {geo_country}'
    )

    render_html(f"""
        <div class='nora-threat-intel-shell'>
            <input class='nora-threat-panel-toggle' type='radio' name='nora-threat-panel' id='nora-panel-none' checked>
            <input class='nora-threat-panel-toggle' type='radio' name='nora-threat-panel' id='nora-panel-reputation'>
            <input class='nora-threat-panel-toggle' type='radio' name='nora-threat-panel' id='nora-panel-asn'>
            <input class='nora-threat-panel-toggle' type='radio' name='nora-threat-panel' id='nora-panel-geographic'>
            <input class='nora-threat-panel-toggle' type='radio' name='nora-threat-panel' id='nora-panel-coverage'>
            <label class='nora-threat-drawer-backdrop' for='nora-panel-none'></label>

            <div class='nora-threat-telemetry-grid'>
                <div class='nora-threat-telemetry-card reputation'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>Reputation</span>
                        <label class='nora-threat-info-dot' for='nora-panel-reputation'>i</label>
                    </div>
                    <div class='nora-threat-telemetry-value red'>{reputation_card_value}</div>
                    <div class='nora-threat-telemetry-meta'>{reputation_card_meta}</div>
                    <div class='nora-threat-telemetry-icon'>!</div>
                </div>

                <div class='nora-threat-telemetry-card asn'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>ASN</span>
                        <label class='nora-threat-info-dot' for='nora-panel-asn'>i</label>
                    </div>
                    <div class='nora-threat-telemetry-value purple'>{asn_value}</div>
                    <div class='nora-threat-telemetry-meta'>{asn_provider}</div>
                    <div class='nora-threat-telemetry-icon'>⌘</div>
                </div>

                <div class='nora-threat-telemetry-card geo'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>Geographic</span>
                        <label class='nora-threat-info-dot' for='nora-panel-geographic'>i</label>
                    </div>
                    <div class='nora-threat-telemetry-value blue'>{geo_country}</div>
                    <div class='nora-threat-telemetry-meta'>{geographic_card_meta}</div>
                    <div class='nora-threat-telemetry-icon'>◉</div>
                </div>

                <div class='nora-threat-telemetry-card coverage'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>Enrichment Coverage</span>
                        <label class='nora-threat-info-dot' for='nora-panel-coverage'>i</label>
                    </div>
                    <div class='nora-threat-telemetry-value green'>{intelligence_coverage}%</div>
                    <div class='nora-threat-telemetry-meta'>{coverage_card_meta}</div>
                    <div class='nora-threat-progress-ring'></div>
                </div>
            </div>

            {drawer_panels_html}

            <div class='nora-threat-grid-two'>
                <div class='nora-threat-card'>
                    <div class='nora-threat-card-title'>Threat Profile</div>
                    <div class='nora-threat-profile-body'>
                        <div class='nora-threat-radar-orb'>◉</div>
                        <div class='nora-threat-detail-list'>
                            <div class='nora-threat-detail-row'>
                                <div class='nora-threat-detail-label'>Primary Threat Source</div>
                                <div class='nora-threat-detail-value'>{top_ip}</div>
                            </div>
                            <div class='nora-threat-detail-row'>
                                <div class='nora-threat-detail-label'>Threat Classification</div>
                                <div class='nora-threat-detail-value red'>{threat_classification}</div>
                            </div>
                            <div class='nora-threat-detail-row'>
                                <div class='nora-threat-detail-label'>Infrastructure Type</div>
                                <div class='nora-threat-detail-value'>{enriched_infrastructure_class}</div>
                            </div>
                            <div class='nora-threat-detail-row'>
                                <div class='nora-threat-detail-label'>Threat Rating</div>
                                <div class='nora-threat-pill'>{threat_rating}</div>
                            </div>
                            <div class='nora-threat-detail-row'>
                                <div class='nora-threat-detail-label'>Assessment Confidence</div>
                                <div style='display:flex;align-items:center;gap:10px;'>
                                    <div class='nora-threat-confidence-bars'>{confidence_bars}</div>
                                    <div class='nora-threat-detail-value'>{assessment_confidence_pct}%</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class='nora-threat-card'>
                    <div class='nora-threat-card-title'>Threat Assessment</div>
                    <div class='nora-threat-assessment-list'>
                        <div class='nora-threat-mini-row'>
                            <div class='nora-threat-mini-label'>Threat Severity</div>
                            <div class='nora-threat-mini-value'>{severity_badge}</div>
                        </div>
                        <div class='nora-threat-mini-row'>
                            <div class='nora-threat-mini-label'>Infrastructure Confidence</div>
                            <div class='nora-threat-mini-value'><div class='nora-threat-confidence-bars'>{infrastructure_confidence}</div></div>
                        </div>
                        <div class='nora-threat-mini-row'>
                            <div class='nora-threat-mini-label'>Behavioural Risk</div>
                            <div class='nora-threat-mini-value'><div class='nora-threat-confidence-bars'>{behavioural_risk}</div></div>
                        </div>
                        <div class='nora-threat-mini-row'>
                            <div class='nora-threat-mini-label'>Enrichment Coverage</div>
                            <div class='nora-threat-mini-value'><div class='nora-threat-confidence-bars'>{coverage_indicator}</div></div>
                        </div>
                        <div class='nora-threat-mini-note'>{assessment_summary}</div>
                    </div>
                </div>
            </div>

            <div class='nora-threat-grid-equal'>
                <div class='nora-threat-card'>
                    <div class='nora-threat-card-title'>Infrastructure Intelligence</div>
                    <div class='nora-threat-mini-row'>
                        <div class='nora-threat-mini-label'>ASN</div>
                        <div class='nora-threat-mini-value'>{asn_value}</div>
                    </div>
                    <div class='nora-threat-mini-row'>
                        <div class='nora-threat-mini-label'>Provider</div>
                        <div class='nora-threat-mini-value'>{asn_provider}</div>
                    </div>
                    <div class='nora-threat-mini-row'>
                        <div class='nora-threat-mini-label'>Geographic Region</div>
                        <div class='nora-threat-mini-value'>{geographic_region}</div>
                    </div>
                    <div class='nora-threat-mini-row'>
                        <div class='nora-threat-mini-label'>Infrastructure Class</div>
                        <div class='nora-threat-mini-value'>{enriched_infrastructure_class}</div>
                    </div>
                    <div class='nora-threat-mini-note'>{infrastructure_assessment}</div>
                </div>

                <div class='nora-threat-card'>
                    <div class='nora-threat-card-title'>Behavioural Profile</div>
                    <div class='nora-threat-behaviour-wrap'>
                        <div>
                            <div class='nora-threat-mini-row'>
                                <div class='nora-threat-mini-label'>Pattern</div>
                                <div class='nora-threat-mini-value'>{behavioural_profile}</div>
                            </div>
                            <div class='nora-threat-mini-row'>
                                <div class='nora-threat-mini-label'>Coordination</div>
                                <div class='nora-threat-mini-value'>{coordination_level}</div>
                            </div>
                            <div class='nora-threat-mini-row'>
                                <div class='nora-threat-mini-label'>Consistency</div>
                                <div class='nora-threat-mini-value'>{consistency_level}</div>
                            </div>
                            <div class='nora-threat-mini-row'>
                                <div class='nora-threat-mini-label'>Persistence</div>
                                <div class='nora-threat-mini-value'>{persistence_level}</div>
                            </div>
                        </div>
                        <div class='nora-threat-fingerprint'>⌾</div>
                    </div>
                </div>
            </div>
        </div>
    """)
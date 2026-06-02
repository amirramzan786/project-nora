import textwrap

import streamlit as st


def render_html(html: str) -> None:
    """Render raw HTML directly without Markdown parsing."""
    st.html(textwrap.dedent(html).strip())


# --- Intelligence Panel Helper ---
def render_intelligence_panel(panel_name: str, panel_data: dict) -> None:
    """Render a native Streamlit intelligence detail panel."""
    if not panel_name:
        return

    title = panel_data.get("title", "Threat Intelligence Detail")
    summary = panel_data.get("summary", "No intelligence summary available.")
    rows = panel_data.get("rows", [])

    row_html = ""
    for label, value in rows:
        row_html += f"""
        <div class='nora-threat-panel-row'>
            <div class='nora-threat-panel-label'>{label}</div>
            <div class='nora-threat-panel-value'>{value}</div>
        </div>
        """

    render_html(f"""
        <div class='nora-threat-intel-panel nora-threat-intel-panel--open'>
            <div class='nora-threat-panel-header'>
                <div>
                    <div class='nora-threat-panel-kicker'>INTELLIGENCE DETAIL</div>
                    <div class='nora-threat-panel-title'>{title}</div>
                </div>
                <div class='nora-threat-panel-status'>ACTIVE</div>
                <a class='nora-threat-panel-close' href='?page=threat_intelligence'>×</a>
            </div>
            <div class='nora-threat-panel-summary'>{summary}</div>
            <div class='nora-threat-panel-grid'>
                {row_html}
            </div>
        </div>
    """)



def render_threat_intelligence(ip_totals, alerts, normal_activity, anomalies):
    """Phase 3.1 Threat Intelligence Workspace"""

    render_html("""
    <div class='nora-workspace-header'>
        <div class='nora-workspace-title'>Threat Intelligence</div>
        <div class='nora-workspace-subtitle'>
            Threat profiling, infrastructure analysis and external intelligence enrichment
        </div>
    </div>
    """)

    threat_count = len(alerts) if alerts else 0
    anomaly_count = len(anomalies) if anomalies else 0

    top_ip = "No Data"
    top_ip_requests = 0

    if ip_totals:
        top_ip, top_ip_requests = max(ip_totals.items(), key=lambda x: x[1])

    intelligence_coverage = min(100, 50 + (threat_count * 2))

    if top_ip_requests > 500:
        threat_rating = "Critical"
    elif top_ip_requests > 100:
        threat_rating = "High"
    else:
        threat_rating = "Medium"

    if anomaly_count > 50:
        behavioural_profile = "Sustained Anomalous Activity"
        coordination_level = "Likely"
        consistency_level = "High"
        persistence_level = "Sustained"
        assessment_reliability = "High"
    elif anomaly_count > 10:
        behavioural_profile = "Moderate Anomalous Activity"
        coordination_level = "Possible"
        consistency_level = "Moderate"
        persistence_level = "Intermittent"
        assessment_reliability = "Medium"
    else:
        behavioural_profile = "Limited Anomalous Activity"
        coordination_level = "Low"
        consistency_level = "Low"
        persistence_level = "Minimal"
        assessment_reliability = "Low"

    if threat_count > 25:
        threat_classification = "Coordinated Reconnaissance Infrastructure"
    elif threat_count > 5:
        threat_classification = "Suspicious Network Activity"
    else:
        threat_classification = "Observed Source Activity"

    # Infrastructure Intelligence (data-driven)
    if top_ip_requests > 500:
        infrastructure_type = "High-Volume Source Infrastructure"
        observed_usage = "Sustained Network Activity"
        infrastructure_assessment = (
            "Traffic volume suggests a highly active source requiring further review."
        )
    elif top_ip_requests > 100:
        infrastructure_type = "Active Source Infrastructure"
        observed_usage = "Elevated Network Activity"
        infrastructure_assessment = (
            "Observed activity exceeds normal levels and may indicate coordinated behaviour."
        )
    else:
        infrastructure_type = "Observed Network Infrastructure"
        observed_usage = "Limited Network Activity"
        infrastructure_assessment = (
            "Limited activity observed from this source during analysis."
        )

    provider_context = "Internal Traffic Analysis"

    # Phase 3.1B enrichment placeholders (to be replaced by live ASN/Geo data)
    asn_value = "AS14061"
    asn_provider = "DigitalOcean LLC"
    geo_country = "Germany"
    geo_city = "Frankfurt"

    assessment_summary = (
        f"Analysis identified {threat_count} detection events and "
        f"{anomaly_count} anomalous observations. Behavioural indicators "
        f"suggest {behavioural_profile.lower()}."
    )

    summary_text = (
        f"Analysis identified {threat_count} threat events, {anomaly_count} anomalies, "
        f"and a primary source of {top_ip}. Current assessment indicates "
        f"{behavioural_profile.lower()} with a {threat_rating.lower()} threat rating."
    )

    intelligence_panels = {
        "Reputation": {
            "title": "Reputation Intelligence",
            "summary": "Reputation assessment is derived from internal detection volume, observed source behaviour and current threat severity.",
            "rows": [
                ("Threat Rating", threat_rating),
                ("Detection Events", threat_count),
                ("Assessment Confidence", "Pending calculation"),
                ("Primary Source", top_ip),
            ],
        },
        "ASN": {
            "title": "ASN Infrastructure Intelligence",
            "summary": "ASN intelligence provides infrastructure ownership and hosting context for the observed source.",
            "rows": [
                ("ASN", asn_value),
                ("Provider", asn_provider),
                ("Infrastructure Class", infrastructure_type),
                ("Observed Usage", observed_usage),
            ],
        },
        "Geographic": {
            "title": "Geographic Intelligence",
            "summary": "Geographic enrichment provides regional context for the observed threat source and supports source concentration analysis.",
            "rows": [
                ("Country", geo_country),
                ("City / Region", geo_city),
                ("Primary Source", top_ip),
                ("Source Requests", top_ip_requests),
            ],
        },
        "Coverage": {
            "title": "Intelligence Coverage",
            "summary": "Coverage indicates how much of the current assessment is supported by available internal intelligence and enrichment context.",
            "rows": [
                ("Coverage", f"{intelligence_coverage}%"),
                ("Internal Signals", threat_count),
                ("Anomaly Signals", anomaly_count),
                ("Reliability", assessment_reliability),
            ],
        },
    }

    confidence_bars = "".join([
        "<span class='nora-threat-confidence-bar'></span>"
        for _ in range(5)
    ])

    if threat_rating == "Critical":
        assessment_confidence_pct = 95
    elif threat_rating == "High":
        assessment_confidence_pct = 82
    else:
        assessment_confidence_pct = 68

    intelligence_panels["Reputation"]["rows"][2] = (
        "Assessment Confidence",
        f"{assessment_confidence_pct}%"
    )

    if threat_rating == "Critical":
        severity_badge = "CRITICAL"
        infrastructure_confidence = "".join([
            "<span class='nora-threat-confidence-bar'></span>"
            for _ in range(5)
        ])
    elif threat_rating == "High":
        severity_badge = "HIGH"
        infrastructure_confidence = "".join([
            "<span class='nora-threat-confidence-bar'></span>"
            for _ in range(4)
        ])
    else:
        severity_badge = "MEDIUM"
        infrastructure_confidence = "".join([
            "<span class='nora-threat-confidence-bar'></span>"
            for _ in range(3)
        ])

    behavioural_risk = "".join([
        "<span class='nora-threat-confidence-bar'></span>"
        for _ in range(2 if anomaly_count < 10 else 4)
    ])

    coverage_indicator = "".join([
        "<span class='nora-threat-confidence-bar'></span>"
        for _ in range(5)
    ])

    if "active_threat_panel" not in st.session_state:
        st.session_state["active_threat_panel"] = None

    selected_panel = st.query_params.get("threat_panel")
    if selected_panel in intelligence_panels:
        st.session_state["active_threat_panel"] = selected_panel

    # Enrichment Telemetry
    render_html(f"""
        <div class='nora-threat-intel-shell'>

            <div class='nora-threat-telemetry-grid'>
                <div class='nora-threat-telemetry-card reputation'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>Reputation</span>
                        <a class='nora-threat-info-dot' href='?page=threat_intelligence&threat_panel=Reputation'>i</a>
                    </div>
                    <div class='nora-threat-telemetry-value red'>{threat_rating}</div>
                    <div class='nora-threat-telemetry-meta'>{threat_count} detection events</div>
                    <div class='nora-threat-telemetry-icon'>!</div>
                </div>

                <div class='nora-threat-telemetry-card asn'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>ASN</span>
                        <a class='nora-threat-info-dot' href='?page=threat_intelligence&threat_panel=ASN'>i</a>
                    </div>
                    <div class='nora-threat-telemetry-value purple'>{asn_value}</div>
                    <div class='nora-threat-telemetry-meta'>{asn_provider}</div>
                    <div class='nora-threat-telemetry-icon'>⌘</div>
                </div>

                <div class='nora-threat-telemetry-card geo'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>Geographic</span>
                        <a class='nora-threat-info-dot' href='?page=threat_intelligence&threat_panel=Geographic'>i</a>
                    </div>
                    <div class='nora-threat-telemetry-value blue'>{geo_country}</div>
                    <div class='nora-threat-telemetry-meta'>{geo_city}</div>
                    <div class='nora-threat-telemetry-icon'>◉</div>
                </div>

                <div class='nora-threat-telemetry-card coverage'>
                    <div class='nora-threat-telemetry-label-row'>
                        <span class='nora-threat-telemetry-label'>Coverage</span>
                        <a class='nora-threat-info-dot' href='?page=threat_intelligence&threat_panel=Coverage'>i</a>
                    </div>
                    <div class='nora-threat-telemetry-value green'>{intelligence_coverage}%</div>
                    <div class='nora-threat-telemetry-meta'>internal intelligence coverage</div>
                    <div class='nora-threat-progress-ring'></div>
                </div>
            </div>

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
                                <div class='nora-threat-detail-value'>{infrastructure_type}</div>
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
                            <div class='nora-threat-mini-label'>Intelligence Coverage</div>
                            <div class='nora-threat-mini-value'><div class='nora-threat-confidence-bars'>{coverage_indicator}</div></div>
                        </div>

                        <div class='nora-threat-mini-note'>
                            {assessment_summary}
                        </div>

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
                        <div class='nora-threat-mini-value'>{geo_city}, {geo_country}</div>
                    </div>
                    <div class='nora-threat-mini-row'>
                        <div class='nora-threat-mini-label'>Infrastructure Class</div>
                        <div class='nora-threat-mini-value'>{infrastructure_type}</div>
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

    active_panel = st.session_state.get("active_threat_panel")
    if active_panel:
        render_intelligence_panel(active_panel, intelligence_panels[active_panel])

    # Evidence Section
    threat_rows = []

    if ip_totals:
        sorted_sources = sorted(
            ip_totals.items(),
            key=lambda item: item[1],
            reverse=True
        )[:10]

        for ip, requests in sorted_sources:
            if requests > 1000:
                risk_level = "Critical"
                reputation_score = "92 / 100"
            elif requests > 500:
                risk_level = "High"
                reputation_score = "84 / 100"
            elif requests > 100:
                risk_level = "Medium"
                reputation_score = "63 / 100"
            else:
                risk_level = "Low"
                reputation_score = "37 / 100"

            threat_rows.append({
                "IP Address": ip,
                "Risk Level": risk_level,
                "ASN / Provider": f"{asn_value} {asn_provider}",
                "Country": geo_country,
                "Reputation Score": reputation_score,
                "Confidence": f"{intelligence_coverage}%"
            })

    table_rows_html = ""

    for row in threat_rows:
        risk_class = row['Risk Level'].lower()

        table_rows_html += f"""
        <tr>
            <td>{row['IP Address']}</td>
            <td><span class='nora-threat-table-pill {risk_class}'>{row['Risk Level']}</span></td>
            <td>{row['ASN / Provider']}</td>
            <td>{row['Country']}</td>
            <td>{row['Reputation Score']}</td>
            <td>{row['Confidence']}</td>
        </tr>
        """

    render_html(f"""
        <div class='nora-threat-table-card'>
            <div class='nora-threat-card-title'>Top Threat Sources</div>

            <table class='nora-threat-source-table'>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Risk</th>
                        <th>ASN / Provider</th>
                        <th>Country</th>
                        <th>Reputation</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows_html}
                </tbody>
            </table>
        </div>
    """)

    render_html(f"""
        <div class='nora-threat-summary-card'>
            <div>
                <div class='nora-threat-card-title'>Threat Intelligence Summary</div>
                <div class='nora-threat-summary-text'>{summary_text}</div>
            </div>
            <div class='nora-threat-summary-icon'>◎</div>
        </div>
        """)
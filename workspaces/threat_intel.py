import textwrap


import streamlit as st
from components.ui_helpers import render_workspace_header
from services.enrichment.ip_enrichment import enrich_ip


def render_html(html: str) -> None:
    """Render raw HTML directly without Markdown parsing."""
    st.html(textwrap.dedent(html).strip())


# Threat Source Classification Engine
def classify_threat_source(requests: int, anomaly_count: int):
    """Simple intelligence classification engine used by Threat Intelligence."""

    if requests > 1000:
        behaviour_classification = "High-Volume Distributed Source"
        threat_likelihood = "Elevated"
        assessment_confidence = 90
    elif requests > 500:
        behaviour_classification = "Sustained Activity Source"
        threat_likelihood = "High"
        assessment_confidence = 82
    elif requests > 100:
        behaviour_classification = "Elevated Activity Source"
        threat_likelihood = "Moderate"
        assessment_confidence = 72
    else:
        behaviour_classification = "Low Volume Source"
        threat_likelihood = "Low"
        assessment_confidence = 60

    if anomaly_count > 50:
        assessment_confidence += 5

    assessment_confidence = min(95, assessment_confidence)

    return {
        "behaviour_classification": behaviour_classification,
        "threat_likelihood": threat_likelihood,
        "assessment_confidence": assessment_confidence,
    }


# Helper to prevent mixed real/fallback enrichment from showing impossible geography.
def normalise_geographic_context(country: str, city: str) -> tuple[str, str]:
    """Prevent mixed real/fallback enrichment from showing impossible geography."""

    country_value = country or "Unknown"
    city_value = city or "Unknown"

    mock_city_country_pairs = {
        "moscow": "Russia",
        "frankfurt": "Germany",
        "london": "United Kingdom",
    }

    expected_country = mock_city_country_pairs.get(city_value.lower())

    if expected_country and country_value != expected_country:
        city_value = "Unknown"

    return country_value, city_value
 
# Helper to render confidence bars based on a percentage score
def build_confidence_bars(score: int) -> str:
    """Render confidence bars based on a percentage score."""

    try:
        numeric_score = int(score)
    except (TypeError, ValueError):
        numeric_score = 0

    if numeric_score >= 85:
        bar_count = 5
    elif numeric_score >= 70:
        bar_count = 4
    elif numeric_score >= 50:
        bar_count = 3
    elif numeric_score >= 30:
        bar_count = 2
    else:
        bar_count = 1

    return "".join([
        "<span class='nora-threat-confidence-bar'></span>"
        for _ in range(bar_count)
    ])


# Helper to safely display abuse scores
def format_abuse_score(score) -> str:
    """Return a safe display value for AbuseIPDB-style scores."""

    if score in [None, "N/A", ""]:
        return "N/A"

    return f"{score}/100"


def render_threat_intelligence(
    ip_totals,
    alerts,
    normal_activity,
    anomalies,
    dataset_mode=None,
    dataset_name=None,
    on_reset_dataset=None,
):
    """Phase 3.1 Threat Intelligence Workspace"""

    render_workspace_header(
        icon="threat",
        title="Threat Intelligence",
        description="Source context, infrastructure indicators and behavioural evidence supporting DDoS detection analysis",
        dataset_mode=dataset_mode,
        dataset_name=dataset_name,
        on_reset_dataset=on_reset_dataset,
        reset_key="reset_dataset_threat_intelligence",
    )

    threat_count = len(alerts) if alerts else 0
    anomaly_count = len(anomalies) if anomalies else 0

    top_ip = "No Data"
    top_ip_requests = 0

    if ip_totals:
        top_ip, top_ip_requests = max(ip_totals.items(), key=lambda x: x[1])

    intelligence_coverage = 0

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
        observed_usage = "Sustained Network Activity"
        infrastructure_assessment = (
            "Traffic volume suggests a highly active source requiring further review."
        )
    elif top_ip_requests > 100:
        observed_usage = "Elevated Network Activity"
        infrastructure_assessment = (
            "Observed activity exceeds normal levels and may indicate coordinated behaviour."
        )
    else:
        observed_usage = "Limited Network Activity"
        infrastructure_assessment = (
            "Limited activity observed from this source during analysis."
        )

    # Phase 3.1 service-layer enrichment.
    # Threat Intelligence now consumes the central IP enrichment service.
    if top_ip == "No Data":
        primary_enrichment = {
            "asn": "N/A",
            "isp": "Unknown Provider",
            "country": "Unknown",
            "city": "Unknown",
            "infrastructure_class": "Unclassified Source Infrastructure",
            "abuse_score": None,
            "known_malicious": False,
            "confidence_score": 0,
        }
    else:
        primary_enrichment = enrich_ip(
            top_ip,
            request_count=top_ip_requests,
            operational_severity=threat_rating.upper(),
            coordinated_activity=anomaly_count > 10,
        )
    asn_value = primary_enrichment.get("asn", "N/A")
    asn_provider = primary_enrichment.get("isp", "Unknown Provider")
    geo_country = primary_enrichment.get("country", "Unknown")
    geo_city = primary_enrichment.get("city", "Unknown")
    geo_country, geo_city = normalise_geographic_context(geo_country, geo_city)
    enriched_infrastructure_class = primary_enrichment.get(
        "infrastructure_class",
        "Unclassified Source Infrastructure",
    )

    primary_abuse_score = primary_enrichment.get("abuse_score", "N/A")
    formatted_primary_abuse_score = format_abuse_score(primary_abuse_score)
    reputation_card_value = (
        formatted_primary_abuse_score
        if formatted_primary_abuse_score != "N/A"
        else threat_rating
    )
    reputation_card_meta = (
        f"{threat_rating} threat rating"
        if primary_abuse_score != "N/A"
        else f"{threat_count} detection events"
    )
    geographic_card_meta = geo_city if geo_city != "Unknown" else "Region pending"

    available_context_signals = sum([
        primary_enrichment.get("abuse_score") not in [None, "N/A"],
        primary_enrichment.get("asn") not in [None, "N/A"],
        primary_enrichment.get("country") not in [None, "Unknown"],
    ])
    intelligence_coverage = round((available_context_signals / 3) * 100)
    coverage_card_meta = f"{available_context_signals}/3 enrichment signals available"

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
            "summary": "Reputation context is derived from request volume, observed source behaviour and current detection severity.",
            "rows": [
                ("Threat Rating", threat_rating),
                (
                    "Abuse Score",
                    formatted_primary_abuse_score,
                ),
                (
                    "Known Malicious",
                    "Yes" if primary_enrichment.get('known_malicious') else "No",
                ),
                (
                    "Infrastructure",
                    enriched_infrastructure_class,
                ),
            ],
        },
        "ASN": {
            "title": "ASN Infrastructure Intelligence",
            "summary": "ASN context provides infrastructure ownership and hosting information for the observed traffic source.",
            "rows": [
                ("ASN", asn_value),
                ("Provider", asn_provider),
                ("Infrastructure Class", enriched_infrastructure_class),
                (
                    "Known Malicious",
                    "Yes" if primary_enrichment.get("known_malicious") else "No",
                ),
            ],
        },
        "Geographic": {
            "title": "Geographic Intelligence",
            "summary": "Geographic context supports source concentration analysis by identifying where observed traffic sources are mapped.",
            "rows": [
                ("Country", geo_country),
                ("City / Region", geo_city),
                ("Primary Source", top_ip),
                (
                    "Confidence Score",
                    f"{primary_enrichment.get('confidence_score', 'N/A')}%",
                ),
            ],
        },
        "Coverage": {
            "title": "Enrichment Coverage",
            "summary": "Enrichment coverage shows which external and internal source-context signals are available for the current primary threat source.",
            "rows": [
                ("Coverage", f"{intelligence_coverage}%"),
                (
                    "AbuseIPDB Data",
                    "Available"
                    if primary_enrichment.get("abuse_score") not in [None, "N/A"]
                    else "Unavailable",
                ),
                (
                    "ASN Context",
                    "Available" if primary_enrichment.get("asn") not in [None, "N/A"] else "Unavailable",
                ),
                (
                    "Geographic Context",
                    "Available" if primary_enrichment.get("country") not in [None, "Unknown"] else "Unavailable",
                ),
                ("Reliability", assessment_reliability),
            ],
        },
    }


    if threat_rating == "Critical":
        fallback_assessment_confidence = 95
    elif threat_rating == "High":
        fallback_assessment_confidence = 82
    else:
        fallback_assessment_confidence = 68

    assessment_confidence_pct = primary_enrichment.get(
        "confidence_score",
        fallback_assessment_confidence,
    )
    confidence_bars = build_confidence_bars(assessment_confidence_pct)


    if threat_rating == "Critical":
        severity_badge = "CRITICAL"
        fallback_infrastructure_confidence = 90
    elif threat_rating == "High":
        severity_badge = "HIGH"
        fallback_infrastructure_confidence = 75
    else:
        severity_badge = "MEDIUM"
        fallback_infrastructure_confidence = 60

    infrastructure_confidence_score = primary_enrichment.get(
        "confidence_score",
        fallback_infrastructure_confidence,
    )
    infrastructure_confidence = build_confidence_bars(infrastructure_confidence_score)
    behavioural_risk_score = 40 if anomaly_count < 10 else 75
    behavioural_risk = build_confidence_bars(behavioural_risk_score)

    coverage_indicator = build_confidence_bars(intelligence_coverage)


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

    # Enrichment Telemetry
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
                        <div class='nora-threat-mini-value'>{geo_country if geo_city == 'Unknown' else f'{geo_city}, {geo_country}'}</div>
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
                fallback_reputation_score = 92
            elif requests > 500:
                risk_level = "High"
                fallback_reputation_score = 84
            elif requests > 100:
                risk_level = "Medium"
                fallback_reputation_score = 63
            else:
                risk_level = "Low"
                fallback_reputation_score = 37

            # Activity Type logic
            if requests > 1000:
                activity_type = "Burst Activity"
            elif requests > 500:
                activity_type = "Sustained Activity"
            elif requests > 100:
                activity_type = "Elevated Activity"
            else:
                activity_type = "Low Volume Source"

            source_enrichment = enrich_ip(
                ip,
                request_count=requests,
                operational_severity=risk_level.upper(),
                coordinated_activity=anomaly_count > 10,
            )
            enrichment_reputation_score = source_enrichment.get(
                "abuse_score",
                fallback_reputation_score,
            )
            reputation_score = format_abuse_score(enrichment_reputation_score)

            intelligence_profile = classify_threat_source(
                requests,
                anomaly_count
            )
            row_country, _ = normalise_geographic_context(
                source_enrichment.get("country", "Unknown"),
                source_enrichment.get("city", "Unknown"),
            )
            row_confidence = source_enrichment.get(
                "confidence_score",
                intelligence_profile["assessment_confidence"],
            )

            threat_rows.append({
                "IP Address": ip,
                "Risk Level": risk_level,
                "ASN / Provider": f"{source_enrichment.get('asn', 'N/A')} {source_enrichment.get('isp', 'Unknown Provider')}",
                "Country": row_country,
                "Reputation Score": reputation_score,
                "Requests": f"{requests:,}",
                "Activity Type": activity_type,
                "Behaviour": intelligence_profile["behaviour_classification"],
                "Likelihood": intelligence_profile["threat_likelihood"],
                "Confidence": f"{row_confidence}%",
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
            <td>{row['Requests']}</td>
            <td>{row['Activity Type']}</td>
            <td>{row['Behaviour']}</td>
            <td>{row['Likelihood']}</td>
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
                        <th>Requests</th>
                        <th>Activity</th>
                        <th>Behaviour</th>
                        <th>Likelihood</th>
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
                <div class='nora-threat-card-title'>Source Context Summary</div>
                <div class='nora-threat-summary-text'>{summary_text}</div>
            </div>
            <div class='nora-threat-summary-icon'>◎</div>
        </div>
        """)
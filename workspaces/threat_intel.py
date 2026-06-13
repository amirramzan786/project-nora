import textwrap


import streamlit as st
from components.ui_helpers import render_workspace_header
from components.threat_overview_section import render_threat_overview_section
from components.threat_sources_table import render_threat_sources_section
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


    render_threat_overview_section(
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
    )
    # Evidence Section

    render_threat_sources_section(
        ip_totals,
        anomaly_count,
        summary_text,
        classify_threat_source,
        normalise_geographic_context,
        format_abuse_score,
    )
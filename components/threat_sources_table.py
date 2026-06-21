

import textwrap

import streamlit as st

from services.enrichment.ip_enrichment import enrich_ip


def render_html(html: str) -> None:
    st.html(textwrap.dedent(html).strip())


def render_threat_sources_section(
    ip_totals,
    anomaly_count,
    summary_text,
    classify_threat_source,
    normalise_geographic_context,
    format_abuse_score,
):

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

            reputation_score = format_abuse_score(
                enrichment_reputation_score
            )

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

            asn_value = source_enrichment.get("asn", "Unknown")
            provider_value = source_enrichment.get(
                "isp",
                "Unknown Provider"
            )

            if str(asn_value).strip() not in ["", "Unknown", "N/A", "None"]:
                asn_provider_display = (
                    f"{asn_value} · {provider_value}"
                    if str(provider_value).strip() not in ["", "Unknown", "None"]
                    else asn_value
                )
            elif str(provider_value).strip() not in ["", "Unknown", "None"]:
                asn_provider_display = provider_value
            else:
                asn_provider_display = "Unknown Provider"

            threat_rows.append({
                "IP Address": ip,
                "Risk Level": risk_level,
                "ASN / Provider": asn_provider_display,
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
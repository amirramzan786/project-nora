"""
Project N.O.R.A.
IP Intelligence Enrichment Service

Phase 3 Foundation:
Central intelligence enrichment ownership layer.

This service will later integrate:
- AbuseIPDB
- ASN intelligence
- Geolocation enrichment
- Threat reputation scoring
- Pattern similarity correlation
- ML-assisted confidence scoring
- Regional threat analysis
"""

from copy import deepcopy
import requests
import streamlit as st
# =====================================================
# ABUSEIPDB API CONFIGURATION
# =====================================================


ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# =====================================================
# ENRICHMENT CACHE
# =====================================================

# Simple in-memory cache used during early Phase 3.
# This prevents repeated API calls for the same IP
# during dashboard refresh cycles.

ENRICHMENT_CACHE = {}


def query_abuseipdb(ip_address):
    """
    Query AbuseIPDB for live threat intelligence.

    Returns None safely if:
    - API key is unavailable
    - request fails
    - timeout occurs
    - rate limits are exceeded
    """

    # -------------------------------------------------
    # Cache Lookup
    # -------------------------------------------------

    if ip_address in ENRICHMENT_CACHE:
        return ENRICHMENT_CACHE[ip_address]

    api_key = st.secrets.get("ABUSEIPDB_API_KEY")

    if not api_key:
        return None

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            ABUSEIPDB_BASE_URL,
            headers=headers,
            params=params,
            timeout=5
        )

        if response.status_code != 200:
            return None

        response_data = response.json().get("data")

        # ---------------------------------------------
        # Cache Successful Response
        # ---------------------------------------------

        if response_data:
            ENRICHMENT_CACHE[ip_address] = response_data

        return response_data

    except Exception:
        return None



# =====================================================
# CANONICAL ENRICHED IP SCHEMA
# =====================================================

ENRICHED_IP_TEMPLATE = {
    "ip_address": "",
    "country": "Unknown",
    "country_code": "UN",
    "country_flag": "🏳️",
    "city": "Unknown",
    "region": "Unknown",
    "asn": "Unknown",
    "isp": "Unknown",
    "regional_risk": "Low",
    "activity_profile": "Unknown",
    "abuse_score": 0,
    "threat_level": "Low",
    "known_malicious": False,
    "confidence_score": 0,
    "request_count": 0,
    "threat_tags": [],
    "attack_patterns": [],
    "threat_infrastructure": "Unknown",
    "traffic_classification": "Unknown",
    "region_cluster": "Unknown",
    "confidence_justification": [],
    "intel_sources": []
}


# =====================================================
# Helper: Country flag from ISO code
# =====================================================

def get_country_flag(country_code):
    """
    Convert ISO country code into emoji flag.

    This lightweight helper supports early
    operational geolocation realism for
    Log Explorer intelligence rendering.
    """

    if not country_code or len(country_code) != 2:
        return "🏳️"

    try:
        return chr(ord(country_code[0].upper()) + 127397) + chr(
            ord(country_code[1].upper()) + 127397
        )
    except Exception:
        return "🏳️"

# =====================================================
# MOCK ENRICHMENT ENGINE
# =====================================================

# NOTE:
# This is intentionally mocked during early Phase 3.
# Live API integrations will be connected later.


# =====================================================
# ADAPTIVE CONFIDENCE ENGINE
# =====================================================


def calculate_confidence_score(enriched_ip):
    """
    Calculate adaptive intelligence confidence based on:
    - reputation scoring
    - malicious indicators
    - request volume
    - behavioural indicators
    - threat classification
    """

    confidence = 0

    # -------------------------------------------------
    # Abuse Reputation Weighting
    # -------------------------------------------------

    abuse_score = enriched_ip.get("abuse_score", 0)

    if abuse_score >= 90:
        confidence += 35
    elif abuse_score >= 70:
        confidence += 25
    elif abuse_score >= 40:
        confidence += 15
    else:
        confidence += 5

    # -------------------------------------------------
    # Malicious Classification
    # -------------------------------------------------

    if enriched_ip.get("known_malicious"):
        confidence += 20

    # -------------------------------------------------
    # Request Volume Analysis
    # -------------------------------------------------

    request_count = enriched_ip.get("request_count", 0)

    if request_count >= 1000:
        confidence += 20
    elif request_count >= 300:
        confidence += 12
    else:
        confidence += 4

    # -------------------------------------------------
    # Threat Tag Density
    # -------------------------------------------------

    threat_tags = enriched_ip.get("threat_tags", [])

    confidence += min(len(threat_tags) * 5, 15)

    # -------------------------------------------------
    # Behavioural Classification
    # -------------------------------------------------

    activity_profile = enriched_ip.get("activity_profile")

    if activity_profile == "High-Risk Behavioural Activity":
        confidence += 15
    elif activity_profile == "Suspicious Behavioural Activity":
        confidence += 8

    # -------------------------------------------------
    # Coordinated Behaviour Weighting
    # -------------------------------------------------

    attack_patterns = enriched_ip.get("attack_patterns", [])

    if len(attack_patterns) >= 2:
        confidence += 8

    # -------------------------------------------------
    # Regional Risk Weighting
    # -------------------------------------------------

    if enriched_ip.get("regional_risk") == "High":
        confidence += 6

    return min(confidence, 100)


def clear_enrichment_cache():
    """
    Clear cached enrichment intelligence.

    This supports future:
    - scheduled refresh workflows
    - cache invalidation
    - adaptive intelligence updates
    """

    ENRICHMENT_CACHE.clear()

def enrich_ip(
    ip_address,
    request_count=0,
    operational_severity="LOW",
    coordinated_activity=False
):
    """
    Generate a standardised enriched IP intelligence object.

    This mock implementation establishes the internal
    intelligence contract before live integrations begin.
    """

    enriched_ip = deepcopy(ENRICHED_IP_TEMPLATE)

    enriched_ip["ip_address"] = ip_address
    enriched_ip["request_count"] = request_count

    # -------------------------------------------------
    # Phase 2.5 Operational Context Injection
    # -------------------------------------------------

    operational_severity = str(
        operational_severity
    ).upper()

    # -------------------------------------------------
    # Live AbuseIPDB Enrichment
    # -------------------------------------------------

    abuseipdb_data = query_abuseipdb(ip_address)

    if abuseipdb_data:

        enriched_ip["abuse_score"] = abuseipdb_data.get(
            "abuseConfidenceScore",
            enriched_ip["abuse_score"]
        )

        enriched_ip["known_malicious"] = (
            enriched_ip["abuse_score"] >= 75
        )

        country_code = abuseipdb_data.get(
            "countryCode",
            enriched_ip["country_code"]
        )

        enriched_ip["country_code"] = country_code
        enriched_ip["country_flag"] = get_country_flag(country_code)

        COUNTRY_NAME_MAP = {
            "GB": "United Kingdom",
            "US": "United States",
            "DE": "Germany",
            "RU": "Russia",
            "FR": "France",
            "CN": "China",
            "HK": "Hong Kong",
            "NL": "Netherlands",
            "SG": "Singapore",
            "JP": "Japan"
        }

        enriched_ip["country"] = COUNTRY_NAME_MAP.get(
            country_code,
            enriched_ip["country"]
        )

        enriched_ip["isp"] = abuseipdb_data.get(
            "isp",
            enriched_ip["isp"]
        )

        enriched_ip["intel_sources"].append(
            "AbuseIPDB"
        )

    # -------------------------------------------------
    # Mock Intelligence Logic
    # -------------------------------------------------

    has_live_intelligence = abuseipdb_data is not None

    if (
        request_count >= 1000
        or (
            operational_severity == "HIGH"
            and coordinated_activity
            and request_count >= 150
        )
    ):
        enriched_ip["threat_level"] = "High"
        enriched_ip["abuse_score"] = max(
            enriched_ip["abuse_score"],
            92
        )
        enriched_ip["known_malicious"] = (
            enriched_ip["known_malicious"]
            or enriched_ip["abuse_score"] >= 75
        )
        enriched_ip["regional_risk"] = "High"
        enriched_ip["activity_profile"] = "High-Risk Behavioural Activity"
        enriched_ip["threat_infrastructure"] = (
            "Distributed Traffic Source"
        )
        enriched_ip["traffic_classification"] = (
            "Volumetric Traffic Behaviour"
        )
        enriched_ip["region_cluster"] = (
            "Unknown Infrastructure Group"
        )
        enriched_ip["threat_tags"] = [
            "DDoS",
            "Distributed Activity",
            "Volumetric Traffic Behaviour"
        ]
        enriched_ip["attack_patterns"] = [
            "Traffic Flooding",
            "Distributed Saturation",
            "Coordinated Burst Correlation",
            "Sustained Throughput Escalation"
        ]
        enriched_ip["confidence_justification"] = [
            "Sustained high-volume traffic activity detected",
            "Behavioural indicators match distributed attack patterns",
            "Multi-region escalation indicators identified",
            "Elevated behavioural confidence indicators observed"
        ]

    elif (
        request_count >= 300
        or (
            operational_severity == "MEDIUM"
            and request_count >= 120
        )
    ):
        enriched_ip["threat_level"] = "Medium"
        enriched_ip["abuse_score"] = max(
            enriched_ip["abuse_score"],
            61
        )
        enriched_ip["regional_risk"] = "Medium"
        enriched_ip["activity_profile"] = "Suspicious Behavioural Activity"
        enriched_ip["threat_infrastructure"] = (
            "Observed Traffic Source"
        )
        enriched_ip["traffic_classification"] = (
            "Escalating Behavioural Traffic"
        )
        enriched_ip["region_cluster"] = (
            "Unknown Infrastructure Group"
        )
        enriched_ip["threat_tags"] = [
            "Suspicious Traffic"
        ]
        enriched_ip["attack_patterns"] = [
            "Repeated Connection Attempts",
            "Burst Correlation Activity",
            "Escalating Request Behaviour"
        ]
        enriched_ip["confidence_justification"] = [
            "Repeated behavioural anomalies observed",
            "Suspicious traffic correlation patterns identified",
            "Elevated traffic activity observed"
        ]

    else:
        enriched_ip["threat_level"] = "Low"
        enriched_ip["abuse_score"] = max(
            enriched_ip["abuse_score"],
            18
        )
        enriched_ip["regional_risk"] = "Low"
        enriched_ip["activity_profile"] = "Low-Risk Behavioural Activity"
        enriched_ip["threat_infrastructure"] = (
            "Observed Traffic Source"
        )
        enriched_ip["traffic_classification"] = (
            "Low Velocity Behaviour"
        )
        enriched_ip["region_cluster"] = (
            "Unknown Infrastructure Group"
        )
        enriched_ip["attack_patterns"] = [
            "Baseline Behaviour Deviation"
        ]
        enriched_ip["confidence_justification"] = [
            "Low-risk behavioural deviation observed",
            "Traffic patterns remain operationally stable"
        ]

    # -------------------------------------------------
    # Adaptive Confidence Calculation
    # -------------------------------------------------

    enriched_ip["confidence_score"] = (
        calculate_confidence_score(enriched_ip)
    )

    if not enriched_ip["intel_sources"]:
        enriched_ip["intel_sources"] = [
            "Behavioural Analysis Only"
        ]

    if not has_live_intelligence:
        enriched_ip["country"] = "Unknown"
        enriched_ip["country_code"] = "UN"
        enriched_ip["country_flag"] = "🏳️"
        enriched_ip["city"] = "Unknown"
        enriched_ip["region"] = "Unknown"
        enriched_ip["asn"] = "Unknown"
        enriched_ip["isp"] = "Unknown"

    return enriched_ip
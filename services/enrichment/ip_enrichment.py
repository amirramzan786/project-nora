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
from pathlib import Path
import ipaddress
import requests
import streamlit as st

from services.scoring.confidence_engine import (
    calculate_intelligence_confidence,
)

try:
    import pycountry
except ImportError:
    pycountry = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

try:
    import geoip2.database
except ImportError:
    geoip2 = None
# =====================================================
# ABUSEIPDB API CONFIGURATION
# =====================================================



ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
GEOIP_DB_PATH = Path("data/geoip/GeoLite2-City.mmdb")

COUNTRY_NAME_FALLBACK_MAP = {
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


def resolve_country_name(country_code, fallback="Unknown"):
    """Resolve an ISO country code into a readable country name.

    Uses pycountry when available for broad ISO coverage and falls back to
    a small built-in map so enrichment remains safe without extra packages.
    """

    if not country_code or country_code == "UN":
        return fallback

    country_code = str(country_code).upper()

    if pycountry is not None:
        country = pycountry.countries.get(alpha_2=country_code)
        if country:
            return country.name

    return COUNTRY_NAME_FALLBACK_MAP.get(country_code, fallback)


def is_routable_ip(ip_address):
    """Return True when an IP is suitable for external ASN/reputation lookup."""

    try:
        ip_obj = ipaddress.ip_address(str(ip_address).strip())
    except ValueError:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def query_asn_intelligence(ip_address):
    """Resolve ASN/provider context using ipwhois when available.

    This is intentionally optional and cached. If ipwhois is unavailable,
    the IP is private/reserved, or lookup fails, None is returned safely.
    """

    if ip_address in ASN_CACHE:
        return ASN_CACHE[ip_address]

    if IPWhois is None or not is_routable_ip(ip_address):
        return None

    try:
        rdap_result = IPWhois(ip_address).lookup_rdap(depth=1)

        asn_data = {
            "asn": rdap_result.get("asn"),
            "asn_description": rdap_result.get("asn_description"),
            "network_name": rdap_result.get("network", {}).get("name"),
            "asn_country_code": rdap_result.get("asn_country_code"),
        }

        ASN_CACHE[ip_address] = asn_data
        return asn_data

    except Exception:
        return None

# =====================================================
# ENRICHMENT CACHE
# =====================================================

# Simple in-memory cache used during early Phase 3.
# This prevents repeated API calls for the same IP
# during dashboard refresh cycles.

ENRICHMENT_CACHE = {}


ASN_CACHE = {}

GEOIP_CACHE = {}
def query_geoip_intelligence(ip_address):
    """Resolve geographic context using GeoLite2 when available."""

    if ip_address in GEOIP_CACHE:
        return GEOIP_CACHE[ip_address]

    if geoip2 is None or not is_routable_ip(ip_address):
        return None

    try:
        if not GEOIP_DB_PATH.exists():
            return None

        with geoip2.database.Reader(str(GEOIP_DB_PATH)) as reader:
            response = reader.city(ip_address)

            geo_data = {
                "country_code": response.country.iso_code,
                "country": response.country.name,
                "city": response.city.name,
                "region": (
                    response.subdivisions.most_specific.name
                    if response.subdivisions
                    else None
                ),
            }

            if not any(
                [
                    geo_data["country_code"],
                    geo_data["country"],
                    geo_data["city"],
                    geo_data["region"],
                ]
            ):
                return None

            GEOIP_CACHE[ip_address] = geo_data
            return geo_data

    except Exception:
        return None


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
    "geoip_source": "Unavailable",
    "asn": "Unknown",
    "asn_description": "Unknown",
    "asn_source": "Unavailable",
    "network_name": "Unknown",
    "isp": "Unknown",
    "regional_risk": "Low",
    "activity_profile": "Unknown",
    "abuse_score": 0,
    "external_reputation_score": 0,
    "behavioural_risk_score": 0,
    "reputation_source": "Unavailable",
    "usage_type": "Unknown",
    "domain": "Unknown",
    "hostnames": [],
    "is_whitelisted": False,
    "is_tor": False,
    "total_reports": 0,
    "distinct_reporters": 0,
    "last_reported_at": "Unknown",
    "threat_level": "Low",
    "known_malicious": False,
    "confidence_score": 0,
    "confidence_band": "Minimal",
    "confidence_evidence": {},
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

        external_reputation_score = abuseipdb_data.get(
            "abuseConfidenceScore",
            enriched_ip["external_reputation_score"]
        )

        enriched_ip["external_reputation_score"] = external_reputation_score
        enriched_ip["abuse_score"] = external_reputation_score
        enriched_ip["reputation_source"] = "AbuseIPDB"

        enriched_ip["known_malicious"] = (
            enriched_ip["external_reputation_score"] >= 75
        )

        country_code = abuseipdb_data.get(
            "countryCode",
            enriched_ip["country_code"]
        )

        enriched_ip["country_code"] = country_code
        enriched_ip["country_flag"] = get_country_flag(country_code)

        enriched_ip["country"] = resolve_country_name(
            country_code,
            fallback=enriched_ip["country"]
        )

        enriched_ip["isp"] = abuseipdb_data.get(
            "isp",
            enriched_ip["isp"]
        )

        # Expanded AbuseIPDB mapping for additional fields
        enriched_ip["usage_type"] = abuseipdb_data.get(
            "usageType",
            enriched_ip["usage_type"]
        )

        enriched_ip["domain"] = abuseipdb_data.get(
            "domain",
            enriched_ip["domain"]
        )

        enriched_ip["hostnames"] = abuseipdb_data.get(
            "hostnames",
            enriched_ip["hostnames"]
        ) or []

        enriched_ip["is_whitelisted"] = abuseipdb_data.get(
            "isWhitelisted",
            enriched_ip["is_whitelisted"]
        )

        enriched_ip["is_tor"] = abuseipdb_data.get(
            "isTor",
            enriched_ip["is_tor"]
        )

        enriched_ip["total_reports"] = abuseipdb_data.get(
            "totalReports",
            enriched_ip["total_reports"]
        )

        enriched_ip["distinct_reporters"] = abuseipdb_data.get(
            "numDistinctUsers",
            enriched_ip["distinct_reporters"]
        )

        enriched_ip["last_reported_at"] = abuseipdb_data.get(
            "lastReportedAt",
            enriched_ip["last_reported_at"]
        )

        enriched_ip["intel_sources"].append(
            "AbuseIPDB"
        )

    # -------------------------------------------------
    # ASN Intelligence Enrichment
    # -------------------------------------------------

    asn_data = query_asn_intelligence(ip_address)

    if asn_data:
        asn_value = asn_data.get("asn")
        asn_description = asn_data.get("asn_description")
        network_name = asn_data.get("network_name")
        asn_country_code = asn_data.get("asn_country_code")

        if asn_value:
            enriched_ip["asn"] = f"AS{asn_value}"

        if asn_description:
            enriched_ip["asn_description"] = asn_description
            if enriched_ip["isp"] == "Unknown":
                enriched_ip["isp"] = asn_description

        if network_name:
            enriched_ip["network_name"] = network_name

        if asn_country_code and enriched_ip["country_code"] == "UN":
            enriched_ip["country_code"] = asn_country_code
            enriched_ip["country"] = resolve_country_name(
                asn_country_code,
                fallback=enriched_ip["country"]
            )
            enriched_ip["country_flag"] = get_country_flag(asn_country_code)

        enriched_ip["asn_source"] = "ipwhois RDAP"
        enriched_ip["intel_sources"].append("ipwhois RDAP")

    # -------------------------------------------------
    # GeoIP Intelligence Enrichment
    # -------------------------------------------------

    geo_data = query_geoip_intelligence(ip_address)

    if geo_data:
        country_code = geo_data.get("country_code")

        if country_code:
            enriched_ip["country_code"] = country_code
            enriched_ip["country_flag"] = get_country_flag(country_code)

        if geo_data.get("country"):
            enriched_ip["country"] = geo_data["country"]

        if geo_data.get("city"):
            enriched_ip["city"] = geo_data["city"]

        if geo_data.get("region"):
            enriched_ip["region"] = geo_data["region"]

        enriched_ip["geoip_source"] = "GeoLite2"
        enriched_ip["intel_sources"].append("GeoLite2")

    # -------------------------------------------------
    # Mock Intelligence Logic
    # -------------------------------------------------

    has_live_intelligence = (
        abuseipdb_data is not None
        or asn_data is not None
        or geo_data is not None
    )

    if (
        request_count >= 1000
        or (
            operational_severity == "HIGH"
            and coordinated_activity
            and request_count >= 150
        )
    ):
        enriched_ip["threat_level"] = "High"
        enriched_ip["behavioural_risk_score"] = 92
        enriched_ip["abuse_score"] = enriched_ip[
            "external_reputation_score"
        ]
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
        enriched_ip["behavioural_risk_score"] = 61
        enriched_ip["abuse_score"] = enriched_ip[
            "external_reputation_score"
        ]
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
        enriched_ip["behavioural_risk_score"] = 18
        enriched_ip["abuse_score"] = enriched_ip[
            "external_reputation_score"
        ]
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
    # Intelligence Confidence Calculation
    # -------------------------------------------------

    intelligence_confidence = (
        calculate_intelligence_confidence(
            external_reputation_score=enriched_ip[
                "external_reputation_score"
            ],
            behavioural_risk_score=enriched_ip[
                "behavioural_risk_score"
            ],
            known_malicious=enriched_ip[
                "known_malicious"
            ],
            total_reports=enriched_ip[
                "total_reports"
            ],
            intelligence_sources=len(
                enriched_ip["intel_sources"]
            ),
        )
    )

    enriched_ip["confidence_score"] = (
        intelligence_confidence["confidence"]
    )

    enriched_ip["confidence_band"] = (
        intelligence_confidence["confidence_band"]
    )

    enriched_ip["confidence_evidence"] = (
        intelligence_confidence["evidence"]
    )

    if not enriched_ip["intel_sources"]:
        enriched_ip["intel_sources"] = [
            "Behavioural Analysis Only"
        ]

    if not has_live_intelligence:
        enriched_ip["country"] = "Unknown"
        enriched_ip["country_code"] = "UN"
        enriched_ip["country_flag"] = "🏳️"
        if enriched_ip["geoip_source"] == "Unavailable":
            enriched_ip["city"] = "Unknown"
            enriched_ip["region"] = "Unknown"
        if enriched_ip["asn_source"] == "Unavailable":
            enriched_ip["asn"] = "Unknown"
            enriched_ip["asn_description"] = "Unknown"
            enriched_ip["network_name"] = "Unknown"
            enriched_ip["isp"] = "Unknown"

    return enriched_ip
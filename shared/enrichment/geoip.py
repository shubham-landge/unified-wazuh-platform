"""GeoIP enricher using MaxMind GeoLite2 (offline, µs lookups).

Falls back gracefully if the database file is not present — enrichment
contribution is 0 (fail-open).

Impossible-travel detection uses Redis to store last-seen location per entity.
"""
from __future__ import annotations

import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Attempt to load maxmind library
try:
    import geoip2.database  # type: ignore
    import geoip2.errors    # type: ignore
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False
    logger.info("geoip2 not installed — GeoIP enrichment disabled (install geoip2 + mmdb)")

# Paths to GeoLite2 databases (override via GEOIP_CITY_DB_PATH / GEOIP_ASN_DB_PATH)
_CITY_DB = os.getenv("GEOIP_CITY_DB_PATH", "/opt/geoip/GeoLite2-City.mmdb")
_ASN_DB  = os.getenv("GEOIP_ASN_DB_PATH",  "/opt/geoip/GeoLite2-ASN.mmdb")

# Private / loopback RFC1918 prefixes to skip
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2",
                     "192.168.", "127.", "::1", "fc", "fd")

# ASNs known to be associated with VPN / Tor exit nodes (sample; extend via config)
_BAD_ASN_ORGS = frozenset([
    "tor project", "mullvad", "nordvpn", "expressvpn", "privateinternetaccess",
    "protonvpn", "surfshark", "cyberghost", "ipvanish",
])


@dataclass
class GeoResult:
    ip: str
    country_iso: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: int = 0
    org: str = ""
    is_tor_vpn: bool = False
    is_bad_asn: bool = False
    is_private: bool = False


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def lookup(ip: str) -> Optional[GeoResult]:
    """Return GeoResult for an IP, or None on any failure (fail-open)."""
    if not ip or _is_private(ip):
        return GeoResult(ip=ip, is_private=True)
    if not _GEOIP2_AVAILABLE:
        return None

    result = GeoResult(ip=ip)

    # City lookup
    if os.path.exists(_CITY_DB):
        try:
            with geoip2.database.Reader(_CITY_DB) as r:
                resp = r.city(ip)
                result.country_iso = resp.country.iso_code or ""
                result.city = resp.city.name or ""
                result.latitude = resp.location.latitude or 0.0
                result.longitude = resp.location.longitude or 0.0
        except Exception:
            pass

    # ASN lookup
    if os.path.exists(_ASN_DB):
        try:
            with geoip2.database.Reader(_ASN_DB) as r:
                resp = r.asn(ip)
                result.asn = resp.autonomous_system_number or 0
                result.org = (resp.autonomous_system_organization or "").lower()
                result.is_tor_vpn = any(kw in result.org for kw in _BAD_ASN_ORGS)
                result.is_bad_asn = result.is_tor_vpn
        except Exception:
            pass

    return result


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def check_impossible_travel(
    entity_key: str,
    new_result: GeoResult,
    redis_client=None,
    speed_kmh: float = 900.0,  # max reasonable travel speed (plane)
) -> bool:
    """Return True if movement from last seen location is physically impossible.

    Uses Redis to persist last-seen (lat, lon, ts) per entity.
    Falls back to False if Redis is unavailable (fail-open).
    """
    if redis_client is None or new_result.is_private or not new_result.latitude:
        return False

    rk = f"geoip_last:{entity_key}"
    now = time.time()

    try:
        raw = redis_client.get(rk)
        if raw:
            lat, lon, ts = (float(x) for x in raw.split(","))
            elapsed_h = (now - ts) / 3600.0
            if elapsed_h > 0:
                dist = _haversine_km(lat, lon, new_result.latitude, new_result.longitude)
                effective_speed = dist / elapsed_h
                if effective_speed > speed_kmh:
                    return True

        # Update last-seen
        redis_client.setex(rk, 86400, f"{new_result.latitude},{new_result.longitude},{now}")
    except Exception as exc:
        logger.debug("impossible-travel redis error: %s", exc)

    return False

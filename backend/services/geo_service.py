"""
Service de géolocalisation : résolution et cache des IP.
"""

import logging
from typing import Dict, Any, Optional, List

from geo.geo_locator import GeoLocator
from geo.ip_resolver import is_public_ip, classify_ip

logger = logging.getLogger(__name__)


_locator = GeoLocator(cache_ttl=86400)


def configure_geo(cache_ttl: int = 86400) -> None:
    global _locator
    _locator = GeoLocator(cache_ttl=cache_ttl)


async def locate_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Géolocalise une IP et retourne les informations."""
    classification = classify_ip(ip)
    if not classification["is_geolocatable"]:
        return {**classification, "geo": None}

    geo_data = await _locator.locate(ip)
    return {**classification, "geo": geo_data}


async def locate_ips(ips: List[str]) -> List[Dict[str, Any]]:
    """Géolocalise un batch d'IPs."""
    results = []
    for ip in ips:
        result = await locate_ip(ip)
        if result:
            results.append(result)
    return results


async def get_attack_map_data(alert_ips: List[str]) -> List[Dict[str, Any]]:
    """Prépare les données pour la carte des attaques."""
    public_ips = [ip for ip in alert_ips if is_public_ip(ip)]
    if not public_ips:
        return []

    geo_results = await _locator.locate_batch(public_ips)
    return [r for r in geo_results if r and r.get("latitude") and r.get("longitude")]

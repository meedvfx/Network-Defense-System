"""
Service de géolocalisation : résolution et cache des IP.
"""

import logging
from typing import Dict, Any, Optional, List

from geo.geo_locator import GeoLocator
from geo.ip_resolver import is_public_ip, classify_ip, sanitize_ip

logger = logging.getLogger(__name__)


# ---- Global Locator ----
_locator = GeoLocator(cache_ttl=86400)


def configure_geo(cache_ttl: int = 86400) -> None:
    """Configure le service de géolocalisation avec un TTL de cache spécifique."""
    global _locator
    _locator = GeoLocator(cache_ttl=cache_ttl)


async def locate_ip(ip: str) -> Optional[Dict[str, Any]]:
    """
    Géolocalise une adresse IP et enrichit les données avec des infos contextuelles.
    Vérifie d'abord si l'IP est privée/réservée avant d'interroger le service externe.
    
    Returns:
        Dict: Données géographiques (pays, ville, lat/lon, ISP) ou None si échec/IP privée.
    """
    try:
        normalized_ip = sanitize_ip(ip)
    except ValueError:
        return {
            "ip": ip,
            "type": "invalid",
            "is_geolocatable": False,
            "geo": None,
            "geo_error": "invalid_ip",
        }

    classification = classify_ip(normalized_ip)
    
    # Optimisation: ne pas géolocaliser les IPs privées (LAN)
    if not classification["is_geolocatable"]:
        return {**classification, "geo": None}

    geo_data = await _locator.locate(normalized_ip)
    if not geo_data:
        return {**classification, "geo": None, "geo_error": "geoip_unavailable"}

    return {**classification, "geo": geo_data}


async def locate_ips(ips: List[str]) -> List[Dict[str, Any]]:
    """
    Géolocalise une liste d'IPs en optimisant les appels (batch/cache).
    Utilisé pour enrichir les listes d'alertes ou de flux.
    """
    results = []
    for ip in ips:
        result = await locate_ip(ip)
        if result:
            results.append(result)
    return results


async def get_attack_map_data(alert_ips: List[str]) -> List[Dict[str, Any]]:
    """
    Prépare les données spécifiquement pour la carte des cyberattaques (World Map).
    Filtre les IPs privées et ne retourne que les points avec coordonnées valides.
    """
    public_ips = []
    for ip in alert_ips:
        try:
            normalized = sanitize_ip(ip)
        except ValueError:
            continue
        if is_public_ip(normalized):
            public_ips.append(normalized)
    
    if not public_ips:
        return []

    geo_results = await _locator.locate_batch(public_ips)
    
    # Filtrage des résultats invalides (sans coordonnées numériques).
    valid_results = []
    for r in geo_results:
        if not r:
            continue
        lat = r.get("latitude")
        lng = r.get("longitude")
        if lat is None or lng is None:
            continue
        valid_results.append(r)

    return valid_results

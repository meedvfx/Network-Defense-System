"""
Service de géolocalisation : résolution et cache des IP.
"""

import logging
from typing import Dict, Any, Optional, List

from geo.geo_locator import GeoLocator
from geo.ip_resolver import is_public_ip, classify_ip

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
    classification = classify_ip(ip)
    
    # Optimisation: ne pas géolocaliser les IPs privées (LAN)
    if not classification["is_geolocatable"]:
        return {**classification, "geo": None}

    geo_data = await _locator.locate(ip)
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
    public_ips = [ip for ip in alert_ips if is_public_ip(ip)]
    
    if not public_ips:
        return []

    geo_results = await _locator.locate_batch(public_ips)
    
    # Filtrage des résultats invalides (sans lat/lon)
    return [r for r in geo_results if r and r.get("latitude") and r.get("longitude")]

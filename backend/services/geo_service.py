"""
Service de géolocalisation : résolution et cache des IP.
"""

import logging
from typing import Dict, Any, Optional, List

from geo.geo_locator import GeoLocator
from geo.ip_resolver import is_public_ip, classify_ip

logger = logging.getLogger(__name__)


class GeoService:
    """Service de géolocalisation des adresses IP."""

    def __init__(self, cache_ttl: int = 86400):
        self.locator = GeoLocator(cache_ttl=cache_ttl)

    async def locate_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Géolocalise une IP et retourne les informations."""
        classification = classify_ip(ip)
        if not classification["is_geolocatable"]:
            return {**classification, "geo": None}

        geo_data = await self.locator.locate(ip)
        return {**classification, "geo": geo_data}

    async def locate_ips(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Géolocalise un batch d'IPs."""
        results = []
        for ip in ips:
            result = await self.locate_ip(ip)
            if result:
                results.append(result)
        return results

    async def get_attack_map_data(self, alert_ips: List[str]) -> List[Dict[str, Any]]:
        """
        Prépare les données pour la carte des attaques.
        Retourne uniquement les IPs publiques avec coordonnées.
        """
        public_ips = [ip for ip in alert_ips if is_public_ip(ip)]
        if not public_ips:
            return []

        geo_results = await self.locator.locate_batch(public_ips)
        return [
            r for r in geo_results
            if r and r.get("latitude") and r.get("longitude")
        ]

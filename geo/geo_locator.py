"""
Géolocalisation des adresses IP via API externe.
Supporte ip-api.com (gratuit) avec cache Redis.
"""

import logging
from typing import Dict, Any, Optional

import httpx

from geo.ip_resolver import is_public_ip, sanitize_ip

logger = logging.getLogger(__name__)

# ---- Constantes ----
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query"
IP_API_BATCH_URL = "http://ip-api.com/batch"


class GeoLocator:
    """
    Service de géolocalisation IP asynchrone.
    Utilise l'API externe ip-api.com pour enrichir les données.
    Intègre un cache mémoire local pour limiter les appels API (Rate Limit 45 req/min).
    """

    def __init__(self, cache_ttl: int = 86400):
        """
        Initialise le service de géolocalisation.
        
        Args:
            cache_ttl: Durée de vie du cache en secondes (Défaut: 24h).
        """
        self.cache_ttl = cache_ttl
        self._local_cache: Dict[str, dict] = {}

    async def locate(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Géolocalise une adresse IP unique.
        
        Logique:
        1. Vérifie si l'IP est publique (inutile de géolocaliser 192.168.x.x).
        2. Vérifie le cache local.
        3. Appelle l'API externe si nécessaire.
        
        Returns:
            Dictionnaire avec Pays, Ville, Lat/Lon, ISP, ASN.
            Retourne None en cas d'erreur technique (timeout, API down).
        """
        ip = sanitize_ip(ip)

        # 1. Filtrage IP Privée/Locale
        if not is_public_ip(ip):
            logger.debug(f"IP {ip} n'est pas publique, géolocalisation ignorée")
            return {
                "ip_address": ip,
                "country": "Local",
                "city": "Local Network",
                "is_local": True,
            }

        # 2. Vérification Cache
        if ip in self._local_cache:
            return self._local_cache[ip]

        # 3. Appel API Externe
        try:
            return await self._query_ip_api(ip)
        except Exception as e:
            logger.error(f"Erreur géolocalisation pour {ip}: {e}")
            return None

    async def _query_ip_api(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Effectue la requête HTTP vers ip-api.com.
        Gère les erreurs réseaux et parse la réponse JSON.
        """
        url = IP_API_URL.format(ip=ip)

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        if data.get("status") == "fail":
            logger.warning(f"ip-api failed for {ip}: {data.get('message')}")
            return None

        # Normalisation des données
        result = {
            "ip_address": ip,
            "country": data.get("country", "Unknown"),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", "Unknown"),
            "latitude": data.get("lat", 0.0),
            "longitude": data.get("lon", 0.0),
            "isp": data.get("isp", "Unknown"),
            "asn": data.get("as", ""),
            "organization": data.get("org", ""),
            "is_local": False,
        }

        # Mise en cache
        self._local_cache[ip] = result
        logger.info(f"Géoloc {ip} → {result['country']}/{result['city']}")

        return result

    async def locate_batch(self, ips: list) -> list:
        """
        Géolocalise une liste d'IPs en une seule requête (Batch).
        Optimisation critique pour les performances du dashboard.
        L'API ip-api.com supporte jusqu'à 100 IPs par requête POST.
        """
        # Filtrer pour ne garder que les IPs publiques
        public_ips = [ip for ip in ips if is_public_ip(ip)]

        if not public_ips:
            return []

        # Tronquer à 100 IPs (limite stricte de l'API gratuite)
        batch = public_ips[:100]

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    IP_API_BATCH_URL,
                    json=[{"query": ip} for ip in batch],
                )
                response.raise_for_status()
                data = response.json()

            results = []
            for item in data:
                if item.get("status") == "success":
                    result = {
                        "ip_address": item.get("query"),
                        "country": item.get("country", "Unknown"),
                        "country_code": item.get("countryCode", ""),
                        "region": item.get("regionName", ""),
                        "city": item.get("city", "Unknown"),
                        "latitude": item.get("lat", 0.0),
                        "longitude": item.get("lon", 0.0),
                        "isp": item.get("isp", "Unknown"),
                        "asn": item.get("as", ""),
                        "is_local": False,
                    }
                    self._local_cache[item["query"]] = result
                    results.append(result)

            return results

        except Exception as e:
            logger.error(f"Erreur batch géolocalisation: {e}")
            return []

    def clear_cache(self):
        """Vide le cache local (utile pour tests ou refresh forcé)."""
        self._local_cache.clear()

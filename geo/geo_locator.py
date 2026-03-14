"""
Géolocalisation des adresses IP via API externe.
Supporte ip-api.com (gratuit) avec cache Redis.
"""

import logging
from typing import Dict, Any, Optional, List

import httpx

from geo.ip_resolver import is_public_ip, sanitize_ip

logger = logging.getLogger(__name__)

# ---- Constantes ----
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query"
IP_API_BATCH_URL = "http://ip-api.com/batch"
IPWHOIS_URL = "https://ipwho.is/{ip}"


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
            return await self._query_with_fallback(ip)
        except Exception as e:
            logger.error(f"Erreur géolocalisation pour {ip}: {e}")
            return None

    async def _query_with_fallback(self, ip: str) -> Optional[Dict[str, Any]]:
        primary = await self._safe_primary_lookup(ip)
        if primary:
            return primary
        return await self._safe_fallback_lookup(ip)

    async def _safe_primary_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._query_ip_api(ip)
        except Exception as e:
            logger.warning(f"Primary GeoIP provider failed for {ip}: {e}")
            return None

    async def _safe_fallback_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            return await self._query_ipwhois(ip)
        except Exception as e:
            logger.warning(f"Fallback GeoIP provider failed for {ip}: {e}")
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

    async def _query_ipwhois(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Fallback GeoIP quand ip-api échoue (timeout, rate limit, indisponibilité).
        """
        url = IPWHOIS_URL.format(ip=ip)
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        if not data.get("success", False):
            logger.warning(f"ipwho.is failed for {ip}: {data.get('message', 'unknown')}")
            return None

        connection = data.get("connection") or {}
        result = {
            "ip_address": ip,
            "country": data.get("country", "Unknown"),
            "country_code": data.get("country_code", ""),
            "region": data.get("region", ""),
            "city": data.get("city", "Unknown"),
            "latitude": data.get("latitude", 0.0),
            "longitude": data.get("longitude", 0.0),
            "isp": connection.get("isp", "Unknown"),
            "asn": connection.get("asn", ""),
            "organization": connection.get("org", ""),
            "is_local": False,
        }

        self._local_cache[ip] = result
        return result

    async def locate_batch(self, ips: List[str]) -> List[Dict[str, Any]]:
        """
        Géolocalise une liste d'IPs en une seule requête (Batch).
        Optimisation critique pour les performances du dashboard.
        L'API ip-api.com supporte jusqu'à 100 IPs par requête POST.
        """
        # Nettoyage + déduplication conservant l'ordre
        normalized_ips: List[str] = []
        seen = set()
        for raw_ip in ips:
            try:
                ip = sanitize_ip(raw_ip)
            except ValueError:
                continue
            if ip in seen:
                continue
            seen.add(ip)
            normalized_ips.append(ip)

        # Filtrer pour ne garder que les IPs publiques
        public_ips = [ip for ip in normalized_ips if is_public_ip(ip)]

        if not public_ips:
            return []

        results: List[Dict[str, Any]] = []

        # Retour immédiat pour les IPs déjà en cache
        remaining = []
        for ip in public_ips:
            cached = self._local_cache.get(ip)
            if cached:
                results.append(cached)
            else:
                remaining.append(ip)

        if not remaining:
            return results

        # Tronquer à 100 IPs (limite stricte de l'API gratuite)
        batch = remaining[:100]

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    IP_API_BATCH_URL,
                    json=[{"query": ip} for ip in batch],
                )
                response.raise_for_status()
                data = response.json()

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

            # Fallback par IP pour les entrées non résolues par le batch
            resolved_ips = {r.get("ip_address") for r in results if r.get("ip_address")}
            missing_ips = [ip for ip in batch if ip not in resolved_ips]
            for ip in missing_ips:
                fallback = await self._query_with_fallback(ip)
                if fallback:
                    results.append(fallback)

            return results

        except Exception as e:
            logger.error(f"Erreur batch géolocalisation: {e}")
            # Dégradation contrôlée: fallback unitaire pour conserver des données exploitables.
            for ip in batch:
                fallback = await self._query_with_fallback(ip)
                if fallback:
                    results.append(fallback)
            return results

    def clear_cache(self):
        """Vide le cache local (utile pour tests ou refresh forcé)."""
        self._local_cache.clear()

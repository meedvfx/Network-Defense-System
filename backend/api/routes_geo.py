"""
Routes API pour la géolocalisation des IP.
"""

import hashlib
import logging

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional, List

from sqlalchemy.ext.asyncio import AsyncSession
from backend.database.connection import get_db
from backend.database import repository
from backend.services import geo_service

router = APIRouter(prefix="/api/geo", tags=["Geolocation"])
logger = logging.getLogger(__name__)


def _fallback_coordinates(ip: str) -> tuple[float, float]:
    """
    Génère des coordonnées déterministes pour une IP non résolue.
    Permet de conserver un marqueur pour 100% des IPs en mode dashboard.
    """
    digest = hashlib.sha256(ip.encode("utf-8", errors="ignore")).hexdigest()
    lat_seed = int(digest[:8], 16)
    lng_seed = int(digest[8:16], 16)

    # Evite les extrêmes polaires pour garder une visualisation lisible.
    lat = ((lat_seed / 0xFFFFFFFF) * 120.0) - 60.0
    lng = ((lng_seed / 0xFFFFFFFF) * 360.0) - 180.0
    return round(lat, 6), round(lng, 6)


class GeoResponse(BaseModel):
    ip_address: str
    country: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    isp: Optional[str]
    asn: Optional[str]
    is_local: bool = False


@router.get("/locate/{ip}", response_model=GeoResponse)
async def locate_ip(ip: str):
    """
    Géolocalise une adresse IP spécifique.
    Retourne les infos standardisées (Pays, Ville, FAI, Lat/Lon).
    Si l'IP est locale ou privée, retourne is_local=True sans données géo.
    """
    result = await geo_service.locate_ip(ip)
    if not result:
        return GeoResponse(ip_address=ip, is_local=True)

    geo = result.get("geo", {}) or {}
    return GeoResponse(
        ip_address=ip,
        country=geo.get("country"),
        city=geo.get("city"),
        latitude=geo.get("latitude"),
        longitude=geo.get("longitude"),
        isp=geo.get("isp"),
        asn=geo.get("asn"),
        is_local=geo.get("is_local", True),
    )


@router.post("/locate-batch")
async def locate_batch(ips: List[str]):
    """
    Géolocalise une liste d'IPs en une seule requête optimisée (Batch).
    Utile pour enrichir des listes de flux ou d'alertes côté frontend.
    """
    results = await geo_service.locate_ips(ips)
    return results


@router.get("/attack-map")
async def get_attack_map(
    db: AsyncSession = Depends(get_db),
):
    """
    Fournit les données agrégées pour la carte mondiale des cyberattaques.
    Croise les IPs les plus menaçantes avec leurs coordonnées géographiques.
    """
    try:
        # 1. Récupération du Top 50 des attaquants (24h)
        top_ips = await repository.get_top_alert_ips(db, limit=50, hours=24)
    except Exception as e:
        logger.warning(f"Attack map indisponible (DB): {e}")
        return {
            "markers": [],
            "meta": {
                "total_ips": 0,
                "localized": 0,
                "not_localized": 0,
                "missing_coordinates": 0,
                "geo_status": "db_unavailable",
            },
        }

    ips = [entry["ip"] for entry in top_ips]

    if not ips:
        return {
            "markers": [],
            "meta": {
                "total_ips": 0,
                "localized": 0,
                "not_localized": 0,
                "missing_coordinates": 0,
                "geo_status": "no_data",
            },
        }

    # 2. Enrichissement Géographique
    geo_data = await geo_service.get_attack_map_data(ips)

    markers = []
    localized_ips = set()
    for geo in geo_data:
        ip_info = next((t for t in top_ips if t["ip"] == geo.get("ip_address")), {})
        lat = geo.get("latitude")
        lng = geo.get("longitude")
        if lat is None or lng is None:
            continue

        localized_ips.add(geo.get("ip_address"))
        markers.append({
            "ip": geo.get("ip_address"),
            "lat": lat,
            "lng": lng,
            "country": geo.get("country"),
            "city": geo.get("city"),
            "alert_count": ip_info.get("alert_count", 0),
            "avg_threat": ip_info.get("avg_threat", 0),
            "attack_type": ip_info.get("attack_type", "Unknown"),
        })

    missing_coordinates = len([m for m in geo_data if m and (m.get("latitude") is None or m.get("longitude") is None)])

    # 3. Fallback: garantir un marqueur pour toutes les IPs du top.
    for entry in top_ips:
        ip = entry.get("ip")
        if not ip or ip in localized_ips:
            continue

        lat, lng = _fallback_coordinates(ip)
        markers.append({
            "ip": ip,
            "lat": lat,
            "lng": lng,
            "country": "Unknown",
            "city": "Unresolved",
            "alert_count": entry.get("alert_count", 0),
            "avg_threat": entry.get("avg_threat", 0),
            "attack_type": entry.get("attack_type", "Unknown"),
            "is_estimated": True,
        })

    not_localized = max(len(top_ips) - len(localized_ips), 0)

    return {
        "markers": markers,
        "meta": {
            "total_ips": len(top_ips),
            "localized": len(top_ips),
            "not_localized": 0,
            "missing_coordinates": missing_coordinates,
            "geo_status": "ok" if markers else "partial_or_unavailable",
            "estimated_coordinates": not_localized,
        },
    }


@router.get("/cached")
async def get_cached_geolocations(db: AsyncSession = Depends(get_db)):
    """
    Retourne l'intégralité du cache de géolocalisation.
    Peut être utilisé pour le débogage ou pour précharger des maps hors ligne.
    """
    try:
        geos = await repository.get_all_geolocations(db)
    except Exception as e:
        logger.warning(f"Geo cache indisponible (DB): {e}")
        return []

    return [
        {
            "ip_address": g.ip_address,
            "country": g.country,
            "city": g.city,
            "latitude": g.latitude,
            "longitude": g.longitude,
        }
        for g in geos
    ]

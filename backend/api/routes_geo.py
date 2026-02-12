"""
Routes API pour la géolocalisation des IP.
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional, List

from sqlalchemy.ext.asyncio import AsyncSession
from backend.database.connection import get_db
from backend.database.repository import GeoRepository
from backend.services.geo_service import GeoService

router = APIRouter(prefix="/api/geo", tags=["Geolocation"])

geo_service = GeoService()


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
    """Géolocalise une adresse IP."""
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
    """Géolocalise un batch d'IPs."""
    results = await geo_service.locate_ips(ips)
    return results


@router.get("/attack-map")
async def get_attack_map(
    db: AsyncSession = Depends(get_db),
):
    """Retourne les données pour la carte des attaques."""
    from backend.database.repository import AlertRepository

    top_ips = await AlertRepository.get_top_ips(db, limit=50, hours=24)
    ips = [entry["ip"] for entry in top_ips]

    if not ips:
        return {"markers": []}

    geo_data = await geo_service.get_attack_map_data(ips)

    markers = []
    for geo in geo_data:
        ip_info = next((t for t in top_ips if t["ip"] == geo.get("ip_address")), {})
        markers.append({
            "ip": geo.get("ip_address"),
            "lat": geo.get("latitude"),
            "lng": geo.get("longitude"),
            "country": geo.get("country"),
            "city": geo.get("city"),
            "alert_count": ip_info.get("alert_count", 0),
            "avg_threat": ip_info.get("avg_threat", 0),
        })

    return {"markers": markers}


@router.get("/cached")
async def get_cached_geolocations(db: AsyncSession = Depends(get_db)):
    """Retourne toutes les géolocalisations en cache DB."""
    geos = await GeoRepository.get_all(db)
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

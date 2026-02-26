import logging
from datetime import datetime
from typing import Dict, Any, List

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import NetworkFlow, Alert, IPGeolocation

logger = logging.getLogger("NDS.Reporting.Metrics")


async def get_period_metrics(session: AsyncSession, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """
    Calcule les métriques de sécurité pour une période donnée.
    """
    try:
        # 1. Total des attaques (Alerts avec decision IN ('confirmed_attack', 'suspicious'))
        query_total_attacks = select(func.count(Alert.id)).where(
            Alert.timestamp >= start_time,
            Alert.timestamp <= end_time,
            Alert.decision.in_(["confirmed_attack", "suspicious"])
        )
        total_attacks_result = await session.execute(query_total_attacks)
        total_attacks = total_attacks_result.scalar_one()

        # 2. Total des flux
        query_total_flows = select(func.count(NetworkFlow.id)).where(
            NetworkFlow.timestamp >= start_time,
            NetworkFlow.timestamp <= end_time
        )
        total_flows_result = await session.execute(query_total_flows)
        total_flows = total_flows_result.scalar_one()

        # 3. Répartition par type d'attaque
        query_attack_types = select(
            Alert.attack_type, func.count(Alert.id).label('count')
        ).where(
            Alert.timestamp >= start_time,
            Alert.timestamp <= end_time,
            Alert.decision.in_(["confirmed_attack", "suspicious"])
        ).group_by(Alert.attack_type).order_by(desc('count'))
        
        attack_types_result = await session.execute(query_attack_types)
        attack_types = {row.attack_type: row.count for row in attack_types_result if row.attack_type}

        # 4. Sévérité moyenne des alertes (0.0 to 1.0)
        query_avg_severity = select(func.avg(Alert.threat_score)).where(
            Alert.timestamp >= start_time,
            Alert.timestamp <= end_time,
            Alert.decision.in_(["confirmed_attack", "suspicious"])
        )
        avg_severity_result = await session.execute(query_avg_severity)
        avg_severity = avg_severity_result.scalar_one() or 0.0

        # 5. Top IP attaquantes
        query_top_ips = select(
            NetworkFlow.src_ip, func.count(Alert.id).label('count')
        ).join(
            Alert, NetworkFlow.id == Alert.flow_id
        ).where(
            Alert.timestamp >= start_time,
            Alert.timestamp <= end_time,
            Alert.decision.in_(["confirmed_attack", "suspicious"])
        ).group_by(NetworkFlow.src_ip).order_by(desc('count')).limit(10)
        
        top_ips_result = await session.execute(query_top_ips)
        top_ips = [{"ip": row.src_ip, "count": row.count} for row in top_ips_result]

        # 6. Top pays attaquants (Enrichissement basique, suppose que IPGeolocation est à jour)
        query_top_countries = select(
            IPGeolocation.country, func.count(Alert.id).label('count')
        ).select_from(Alert).join(
            NetworkFlow, Alert.flow_id == NetworkFlow.id
        ).join(
            IPGeolocation, NetworkFlow.src_ip == IPGeolocation.ip_address
        ).where(
            Alert.timestamp >= start_time,
            Alert.timestamp <= end_time,
            Alert.decision.in_(["confirmed_attack", "suspicious"])
        ).group_by(IPGeolocation.country).order_by(desc('count')).limit(5)
        
        try:
            top_countries_result = await session.execute(query_top_countries)
            top_countries = [{"country": row.country or "Unknown", "count": row.count} for row in top_countries_result]
        except Exception as e:
            logger.warning(f"Impossible de récupérer les pays (peut-être pas de liaison join directe) : {e}")
            top_countries = []

        return {
            "total_attacks": total_attacks,
            "total_flows": total_flows,
            "attack_ratio_percent": round((total_attacks / total_flows * 100) if total_flows > 0 else 0, 2),
            "avg_severity_score": round(avg_severity, 2),
            "attack_types": attack_types,
            "top_ips": top_ips,
            "top_countries": top_countries,
        }
        
    except Exception as e:
        logger.error(f"Erreur lors du calcul des métriques de reporting: {e}")
        return {
            "total_attacks": 0,
            "total_flows": 0,
            "attack_ratio_percent": 0.0,
            "avg_severity_score": 0.0,
            "attack_types": {},
            "top_ips": [],
            "top_countries": [],
        }

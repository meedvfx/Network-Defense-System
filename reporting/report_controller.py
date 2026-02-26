import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from reporting.metrics_engine import get_period_metrics
from reporting.trend_analysis import analyze_trends
from reporting.threat_index import calculate_threat_index
from reporting.prompt_builder import build_prompt_from_stats
from reporting.llm_engine import generate_llm_analysis
from reporting.report_formatter import generate_markdown_report
from reporting.pdf_exporter import create_pdf_from_markdown

logger = logging.getLogger("NDS.Reporting.Controller")

class ReportingController:
    """
    Orchestrateur principal du module de génération de rapports.
    """
    
    @staticmethod
    async def generate_report(
        session: AsyncSession,
        period_hours: int = 24,
        detail_level: str = "Technical",
        export_format: str = "json"
    ) -> Dict[str, Any]:
        """
        Génère un rapport de sécurité complet.
        
        Args:
            session: SQLAlchemy async session
            period_hours: Période d'analyse en heures (ex: 24, 168 pour 7j, 720 pour 30j)
            detail_level: "Technical" ou "Executive"
            export_format: "json", "markdown" ou "pdf"
            
        Returns:
            Dictionnaire contenant le rapport final selon le format demandé.
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=period_hours)
        
        logger.info(f"Début de génération de rapport ({period_hours}h) - {start_time} to {end_time}")
        
        # 1. Pipeline de données
        # On calcule les métriques de la période
        metrics = await get_period_metrics(session, start_time, end_time)
        
        # On calcule les tendances (comparaison vs l'équivalent passé)
        # On passe les métriques déjà calculées pour éviter une requête DB redondante
        trends = await analyze_trends(session, start_time, end_time, current_metrics=metrics)
        
        # On détermine le Threat Index algorithmique
        threat_idx = calculate_threat_index(metrics, trends)
        
        # 2. IA / LLM Pipeline
        # On construit le prompt sécurisé
        prompt = build_prompt_from_stats(
            start_time=start_time,
            end_time=end_time,
            metrics=metrics,
            trends=trends,
            threat_index=threat_idx,
            detail_level=detail_level
        )
        
        # On appelle le LLM gratuit local/cloud configuré
        llm_output = await generate_llm_analysis(prompt)
        
        # 3. Formatage et Export
        if export_format == "json":
            return {
                "period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "hours": period_hours
                },
                "threat_index": threat_idx,
                "metrics": metrics,
                "trends": trends,
                "llm_analysis": llm_output
            }
            
        elif export_format == "markdown":
            md_text = generate_markdown_report(
                start_time=start_time,
                end_time=end_time,
                metrics=metrics,
                trends=trends,
                threat_index=threat_idx,
                llm_analysis=llm_output
            )
            return {"markdown": md_text}
            
        elif export_format == "pdf":
            md_text = generate_markdown_report(
                start_time=start_time,
                end_time=end_time,
                metrics=metrics,
                trends=trends,
                threat_index=threat_idx,
                llm_analysis=llm_output
            )
            pdf_path = create_pdf_from_markdown(md_text)
            return {"pdf_path": pdf_path}
            
        else:
            raise ValueError(f"Format d'export non supporté : {export_format}")

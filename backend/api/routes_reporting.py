import os
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Literal

from backend.database.connection import get_db
from backend.core.security import verify_api_key
from reporting.report_controller import ReportingController

router = APIRouter(
    prefix="/api/reporting",
    tags=["Reporting"],
    responses={404: {"description": "Non trouvé"}},
)

@router.post("/generate", summary="Génère un rapport de sécurité (LLM)")
async def generate_soc_report(
    period_hours: int = Query(24, description="Période en heures (ex: 24, 168=7j, 720=30j)"),
    detail_level: Literal["Technical", "Executive"] = Query("Technical", description="Niveau de détail du LLM"),
    export_format: Literal["json", "markdown", "pdf"] = Query("json", description="Format de sortie"),
    db: AsyncSession = Depends(get_db)
):
    """
    Génère un rapport de sécurité complet à l'aide des métriques de base de données, 
    combinées à une analyse intelligente générée par un LLM Open Source (Ollama/Groq).
    """
    try:
        result = await ReportingController.generate_report(
            session=db,
            period_hours=period_hours,
            detail_level=detail_level,
            export_format=export_format
        )
        
        # Si c'est un PDF, il retourne un chemin temporaire, on utilise FileResponse
        if export_format == "pdf":
            pdf_path = result.get("pdf_path")
            if not pdf_path or not os.path.exists(pdf_path):
                raise HTTPException(status_code=500, detail="Erreur lors de la génération du PDF.")
                
            return FileResponse(
                path=pdf_path,
                filename="SOC_Report.pdf",
                media_type="application/pdf",
                # On pourrait le supprimer en background task post-response
            )
            
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

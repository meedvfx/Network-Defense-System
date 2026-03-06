"""
Routes API pour le module de reporting IA.
Inclut la génération de rapports et la gestion de la configuration LLM.
"""

import os
from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import FileResponse
from fastapi.background import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Literal, Optional

from backend.database.connection import get_db
from backend.core.security import verify_api_key
from reporting.report_controller import ReportingController
from backend.services.llm_config_service import (
    get_public_config,
    save_config,
    PROVIDERS,
)
from reporting.llm_engine import test_llm_connection

router = APIRouter(
    prefix="/api/reporting",
    tags=["Reporting"],
    dependencies=[Depends(verify_api_key)],
    responses={404: {"description": "Non trouvé"}},
)

# ──────────────────────────────────────────────────────────────────────────────
# Schémas Pydantic
# ──────────────────────────────────────────────────────────────────────────────

class LLMConfigPayload(BaseModel):
    """Payload pour la sauvegarde de la configuration LLM."""
    provider:         str   = Field(..., description="Identifiant du fournisseur LLM")
    model:            str   = Field(..., description="Nom du modèle")
    api_key:          str   = Field("",  description="Clé API (vide = pas de changement si masquée)")
    temperature:      float = Field(0.2, ge=0.0, le=2.0, description="Créativité du LLM (0=déterministe)")
    max_tokens:       int   = Field(2048, ge=64, le=32768, description="Tokens maximum en sortie")
    ollama_base_url:  str   = Field("http://localhost:11434/api", description="URL du serveur Ollama (si applicable)")


class TestConnectionPayload(BaseModel):
    """Payload pour tester une connexion LLM (la clé peut être masquée)."""
    provider:         str           = Field(..., description="Identifiant du fournisseur LLM")
    model:            str           = Field(..., description="Nom du modèle")
    api_key:          Optional[str] = Field(None, description="Clé API en clair (None = utilise la clé stockée)")
    ollama_base_url:  str           = Field("http://localhost:11434/api")


# ──────────────────────────────────────────────────────────────────────────────
# Configuration LLM
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/llm-config", summary="Récupère la configuration LLM actuelle (clé masquée)")
async def get_llm_config():
    """
    Retourne la configuration LLM active.
    La clé API n'est jamais retournée en clair — seule une version masquée est fournie.
    """
    return get_public_config()


@router.post("/llm-config", summary="Sauvegarde la configuration LLM")
async def set_llm_config(payload: LLMConfigPayload):
    """
    Sauvegarde la configuration LLM côté serveur.
    Si la clé API contient '****' (valeur masquée), l'ancienne clé est conservée.
    """
    if payload.provider not in PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Fournisseur '{payload.provider}' non supporté. "
                   f"Valeurs acceptées : {list(PROVIDERS.keys())}",
        )

    ok = save_config(payload.model_dump())
    if not ok:
        raise HTTPException(status_code=500, detail="Échec de la sauvegarde de la configuration.")

    return {"success": True, "message": "Configuration LLM sauvegardée.", **get_public_config()}


@router.post("/test-connection", summary="Teste la connexion avec le LLM configuré")
async def test_connection(payload: TestConnectionPayload):
    """
    Effectue une requête minimale pour valider la configuration LLM.
    Si api_key est None ou masquée, la clé stockée sur le serveur est utilisée.
    """
    from backend.services.llm_config_service import load_config

    stored = load_config()

    # Résoudre la clé API : si la clé transmise est absente/masquée, utiliser la clé stockée
    api_key = payload.api_key or ""
    if not api_key or "****" in api_key:
        api_key = stored.get("api_key", "")

    config = {
        "provider":        payload.provider,
        "model":           payload.model,
        "api_key":         api_key,
        "ollama_base_url": payload.ollama_base_url,
    }

    result = await test_llm_connection(config)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Génération de rapports
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/generate", summary="Génère un rapport de sécurité (LLM)")
async def generate_soc_report(
    period_hours:  int = Query(24,          description="Période en heures (ex: 24, 168=7j, 720=30j)"),
    detail_level:  Literal["Technical", "Executive"] = Query("Technical", description="Niveau de détail du LLM"),
    export_format: Literal["json", "markdown", "pdf"] = Query("json",      description="Format de sortie"),
    db: AsyncSession = Depends(get_db),
):
    """
    Génère un rapport de sécurité SOC complet.
    Utilise automatiquement le fournisseur LLM configuré via /api/reporting/llm-config.
    """
    try:
        result = await ReportingController.generate_report(
            session=db,
            period_hours=period_hours,
            detail_level=detail_level,
            export_format=export_format,
        )

        if export_format == "pdf":
            pdf_path = result.get("pdf_path")
            if not pdf_path or not os.path.exists(pdf_path):
                raise HTTPException(status_code=500, detail="Erreur lors de la génération du PDF.")

            background_tasks = BackgroundTasks()
            background_tasks.add_task(os.unlink, pdf_path)

            return FileResponse(
                path=pdf_path,
                filename="SOC_Report.pdf",
                media_type="application/pdf",
                background=background_tasks,
            )

        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

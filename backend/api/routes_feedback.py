"""
Routes pour le feedback des analystes SOC (auto-learning).
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from backend.database.connection import get_db
from backend.database import repository

router = APIRouter(prefix="/api/feedback", tags=["Feedback"])


class FeedbackRequest(BaseModel):
    """Modèle pour soumettre un feedback."""
    alert_id: str
    analyst_label: str # ex: 'benign', 'malicious', 'ddos'
    notes: Optional[str] = None


@router.post("/")
async def submit_feedback(
    request: FeedbackRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Enregistre le feedback d'un expert sur une alerte spécifique.
    Ces données constituent le "Ground Truth" pour le ré-entraînement futur des modèles.
    """
    feedback = await repository.create_feedback(
        db,
        {
            "alert_id": request.alert_id,
            "analyst_label": request.analyst_label,
            "notes": request.notes,
        },
    )
    return {
        "status": "submitted",
        "feedback_id": str(feedback.id),
        "message": "Feedback enregistré pour le prochain cycle de retraining",
    }


@router.get("/stats")
async def get_feedback_stats(db: AsyncSession = Depends(get_db)):
    """
    Retourne des métriques sur la boucle de feedback.
    Permet de savoir si assez de données sont disponibles pour lancer un entraînement.
    """
    unused_count = await repository.count_unused_feedback(db)
    return {
        "unused_feedback_count": unused_count,
        "ready_for_retrain": unused_count >= 100, # Seuil arbitraire pour déclencher un batch
    }


@router.get("/unused")
async def get_unused_feedback(db: AsyncSession = Depends(get_db)):
    """
    Récupère la liste des labels validés non encore utilisés par le modèle.
    C'est cette liste qui sera consommée par le pipeline d'entraînement offline.
    """
    feedbacks = await repository.get_unused_feedback(db)
    return [
        {
            "id": str(f.id),
            "alert_id": str(f.alert_id),
            "analyst_label": f.analyst_label,
            "notes": f.notes,
            "created_at": f.created_at.isoformat(),
        }
        for f in feedbacks
    ]

"""
Routes pour le feedback des analystes SOC (auto-learning).
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from backend.database.connection import get_db
from backend.database.repository import FeedbackRepository

router = APIRouter(prefix="/api/feedback", tags=["Feedback"])


class FeedbackRequest(BaseModel):
    alert_id: str
    analyst_label: str
    notes: Optional[str] = None


@router.post("/")
async def submit_feedback(
    request: FeedbackRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Soumet un feedback d'analyste sur une alerte.
    Utilisé pour l'auto-learning et le retraining.
    """
    feedback = await FeedbackRepository.create(
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
    """Statistiques sur les feedbacks (utilisés/non utilisés)."""
    unused_count = await FeedbackRepository.count_unused(db)
    return {
        "unused_feedback_count": unused_count,
        "ready_for_retrain": unused_count >= 100,
    }


@router.get("/unused")
async def get_unused_feedback(db: AsyncSession = Depends(get_db)):
    """Liste les feedbacks non encore utilisés pour l'entraînement."""
    feedbacks = await FeedbackRepository.get_unused(db)
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

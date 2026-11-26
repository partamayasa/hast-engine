# backend/routers/v1/research.py
"""Data riset (metadata dataset, evaluasi model)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.routers.deps import get_db
from backend.repositories import research as research_repo

router = APIRouter(prefix="/api/v1", tags=["Riset"])


@router.get("/research/dataset-metadata")
def dataset_metadata(db: Session = Depends(get_db)):
    return {"metadata": research_repo.load_dataset_metadata(db)}


@router.get("/research/class-distribution")
def class_distribution(db: Session = Depends(get_db)):
    return {"rows": research_repo.load_class_distribution(db)}


@router.get("/research/model-evaluation")
def model_evaluation(algorithm: str = "Random Forest Regressor", db: Session = Depends(get_db)):
    return {"evaluation": research_repo.load_model_evaluation(db, algorithm)}

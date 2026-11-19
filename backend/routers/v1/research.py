# backend/routers/v1/research.py
"""Data riset (metadata dataset, evaluasi model) dan kuesioner SUS."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.routers.deps import CurrentUser, get_db, require_permission
from backend.repositories import research as research_repo

router = APIRouter(prefix="/api/v1", tags=["Riset & SUS"])


@router.get("/research/dataset-metadata")
def dataset_metadata(db: Session = Depends(get_db)):
    return {"metadata": research_repo.load_dataset_metadata(db)}


@router.get("/research/class-distribution")
def class_distribution(db: Session = Depends(get_db)):
    return {"rows": research_repo.load_class_distribution(db)}


@router.get("/research/model-evaluation")
def model_evaluation(algorithm: str = "Random Forest Regressor", db: Session = Depends(get_db)):
    return {"evaluation": research_repo.load_model_evaluation(db, algorithm)}


class SusInput(BaseModel):
    respondent_name: str = Field(min_length=1, max_length=128)
    profession: str = Field(min_length=1, max_length=128)
    answers: dict[str, int]
    ui_version: str | None = Field(default="v2-dss", max_length=32)


@router.post("/sus")
def submit_sus(data: SusInput, db: Session = Depends(get_db)):
    """Publik: responden mengisi kuesioner tanpa akun (sama seperti v1)."""
    new_id = research_repo.save_sus_response(db, data.respondent_name, data.profession, data.answers, data.ui_version)
    raw, score, acceptability, grade = research_repo.calculate_sus_score(data.answers)
    return {"status": "success", "id": new_id, "raw_score": raw, "sus_score": score,
            "acceptability": acceptability, "grade_scale": grade}


@router.get("/sus")
def list_sus(db: Session = Depends(get_db), _user: CurrentUser = Depends(require_permission("sus.read"))):
    """Nama responden adalah data pribadi, sehingga melihat daftarnya memerlukan hak akses."""
    return {"rows": research_repo.load_all_sus_responses(db)}

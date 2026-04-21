"""FastAPI entrypoint for the scalable scanner service."""
from datetime import datetime
import os
import uuid

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from .auth import create_access_token, require_role, require_user, verify_password
from .dashboard import router as dashboard_router
from .db import Base, engine, get_db
from .models import ScanJob, User
from .schemas import LoginRequest, ReportSummary, ScanResponse


app = FastAPI(title="AI Security Scanner Service", version="2.0.0")
app.include_router(dashboard_router)
Base.metadata.create_all(bind=engine)


@app.get("/healthz")
def healthcheck():
    return {"status": "ok"}


@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_access_token(str(user.id), user.role), "token_type": "bearer"}


@app.post("/scan", response_model=ScanResponse)
async def create_scan(
    upload: UploadFile = File(...),
    claims: dict = Depends(require_user),
    db: Session = Depends(get_db),
):
    scan_id = uuid.uuid4().hex
    uploads_dir = os.getenv("UPLOAD_DIR", "/tmp/security-scanner/uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    destination = os.path.join(uploads_dir, f"{scan_id}-{upload.filename}")

    with open(destination, "wb") as handle:
        while chunk := await upload.read(1024 * 1024):
            handle.write(chunk)

    job = ScanJob(
        id=scan_id,
        user_id=int(claims["sub"]),
        status="queued",
        target_name=upload.filename,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(job)
    db.commit()

    # Replace this import with your task queue wiring in production.
    # from platform.worker.tasks import process_scan
    # process_scan.delay(scan_id, destination)

    return ScanResponse(
        id=job.id,
        status=job.status,
        target_name=job.target_name,
        created_at=job.created_at,
    )


@app.get("/scan/{scan_id}")
def get_scan(
    scan_id: str,
    claims: dict = Depends(require_user),
    db: Session = Depends(get_db),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if claims.get("role") != "admin" and int(claims["sub"]) != job.user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {
        "id": job.id,
        "status": job.status,
        "target_name": job.target_name,
        "report_path": job.report_path,
        "created_at": job.created_at,
        "summary_json": job.summary_json,
    }


@app.get("/reports", response_model=list[ReportSummary])
def get_reports(
    claims: dict = Depends(require_role("user")),
    db: Session = Depends(get_db),
):
    query = db.query(ScanJob)
    if claims.get("role") != "admin":
        query = query.filter(ScanJob.user_id == int(claims["sub"]))
    jobs = query.order_by(ScanJob.created_at.desc()).limit(100).all()
    return [
        ReportSummary(
            scan_id=job.id,
            target_name=job.target_name,
            status=job.status,
            created_at=job.created_at,
        )
        for job in jobs
    ]

# Microservice Skeleton

This folder contains a production-oriented skeleton for evolving the scanner into a queue-backed service:

- `api/`: FastAPI application, auth helpers, models, schemas, dashboard endpoints
- `worker/`: Celery task workers that invoke the shared scanner engine
- `requirements.txt`: dependencies for the service stack
- `Dockerfile`: multi-stage production image

## Suggested structure

```text
scanner_service/
  api/
    auth.py
    dashboard.py
    db.py
    main.py
    models.py
    schemas.py
  worker/
    tasks.py
  Dockerfile
  requirements.txt
```

## Runtime

- API: FastAPI + Gunicorn/Uvicorn workers
- Queue: Celery + Redis
- Database: PostgreSQL
- Scanner engine: reuses `src/scanner/file_scanner.py` and `src/ai/analyzer.py`

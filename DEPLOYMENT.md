# Free Deployment Guide

## Best free option: Render

This project now includes a minimal Flask web app in `src/web_app.py` and a `render.yaml` blueprint.

### 1. Prepare the repo

- Commit the project to GitHub.
- Make sure `requirements.txt` and `render.yaml` are included.

### 2. Deploy on Render

1. Create a Render account.
2. Click `New` -> `Blueprint`.
3. Connect your GitHub repository.
4. Render will detect `render.yaml`.
5. Deploy the service.

### 3. What Render will run

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --chdir src web_app:app`

### 4. After deploy

- Open the deployed URL.
- Upload a supported file.
- Review findings in the browser.

## Local web run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
make web
```

Then open `http://127.0.0.1:5000`.

## Other low-cost or free-friendly options

- Render: easiest for this repo because it supports Python web services directly.
- Koyeb: good free starter option for one web service with scale-to-zero behavior.
- Railway: usable for testing, but its free tier is credit-based and more limited for ongoing hosting.

## Notes

- The Flask web app scans uploaded files, not the entire server filesystem.
- For team use, add authentication before exposing this publicly.
- Free plans are best for demos, internal previews, and small usage.

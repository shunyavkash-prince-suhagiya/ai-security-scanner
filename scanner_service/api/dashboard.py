"""Simple dashboard HTML for scan metrics."""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return """
    <html>
      <head><title>Security Dashboard</title></head>
      <body style="font-family: sans-serif; max-width: 960px; margin: 2rem auto;">
        <h1>Security Dashboard</h1>
        <ul>
          <li>Total vulnerabilities</li>
          <li>Risk distribution chart</li>
          <li>Top risky files</li>
          <li>Timeline of scans</li>
        </ul>
        <p>Connect this page to /reports and /scan/{id} for live data.</p>
      </body>
    </html>
    """

"""UI page routes — serves the multi-page Tidewall dashboard."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, RedirectResponse

from app.auth.dependencies import require_role

router = APIRouter()

PAGES_DIR = os.path.join(os.path.dirname(__file__), "..", "static", "pages")


@router.get("/dashboard", dependencies=[Depends(require_role("viewer"))])
async def dashboard_redirect():
    return RedirectResponse(url="/ui/visibility")


@router.get("/ui/{page}", dependencies=[Depends(require_role("viewer"))])
async def serve_page(page: str):
    allowed = {"visibility", "findings", "policies", "sandbox"}
    if page not in allowed:
        page = "findings"
    path = os.path.join(PAGES_DIR, f"{page}.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")
    return FileResponse(os.path.join(PAGES_DIR, "findings.html"), media_type="text/html")

from fastapi.responses import HTMLResponse
from fastapi import Request
from guppy_ics.web.deps import templates
from guppy_ics.web.routes.upload import router as upload_router
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from guppy_ics.web.routes.calibration import router as calibration_router
from guppy_ics.web.routes.progress import router as progress_router
from guppy_ics.web.routes.help import router as help_router

app = FastAPI(title="Guppy ICS")

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(calibration_router)
app.include_router(upload_router)
app.include_router(progress_router)
app.include_router(help_router)

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


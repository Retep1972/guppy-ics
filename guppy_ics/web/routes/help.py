from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from guppy_ics.web.deps import templates

router = APIRouter()

@router.get("/help", response_class=HTMLResponse)
def help_page(request: Request):
    return templates.TemplateResponse(
        "help.html",
        {"request": request},
    )

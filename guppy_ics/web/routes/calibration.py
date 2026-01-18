from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from guppy_ics.analysis.calibration import run_modbus_calibration
from guppy_ics.web.deps import templates

router = APIRouter()


@router.get("/calibration", response_class=HTMLResponse)
def calibration_page(request: Request):
    return templates.TemplateResponse(
        "calibration.html",
        {"request": request}
    )


@router.post("/calibration/run", response_class=HTMLResponse)
def run_calibration(request: Request):
    state = run_modbus_calibration()

    assets = []
    for a in state.assets.values():
        a = dict(a)
        a["protocols"] = sorted(list(a["protocols"]))
        assets.append(a)

    communications = list(state.communications.values())

    return templates.TemplateResponse(
        "calibration_result.html",
        {
            "request": request,
            "summary": state.summary(),
            "assets": assets,
            "communications": communications,
        }
    )

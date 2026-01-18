from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from guppy_ics.web.progress import ProgressBus

router = APIRouter()


def sse_event_stream(bus: ProgressBus):
    for count in bus.events():
        yield f"data: {count}\n\n"

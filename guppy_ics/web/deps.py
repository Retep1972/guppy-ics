from fastapi.templating import Jinja2Templates
from importlib.resources import files

templates = Jinja2Templates(
    directory=str(files("guppy_ics.web").joinpath("templates"))
)

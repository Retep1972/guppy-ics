import threading


class CancelToken:
    """
    Cooperative cancellation token.
    """
    def __init__(self):
        self._event = threading.Event()

    def cancel(self):
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


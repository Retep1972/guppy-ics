import queue
from typing import Optional


class ProgressBus:
    """
    Thread-safe progress message queue for a single analysis run.
    """

    def __init__(self):
        self._queue: queue.Queue[int] = queue.Queue()
        self._done = False

    def push(self, count: int):
        self._queue.put(count)

    def done(self):
        self._done = True
        self._queue.put(None)

    def events(self):
        """
        Generator for SSE.
        """
        while True:
            value = self._queue.get()
            if value is None:
                break
            yield value

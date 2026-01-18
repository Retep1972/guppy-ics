from abc import ABC, abstractmethod
from typing import Iterable


class PacketSource(ABC):
    """
    Abstract packet source.
    Must be passive-only.
    """

    @abstractmethod
    def packets(self) -> Iterable[object]:
        """
        Yield packets one-by-one.
        Must not send traffic.
        """
        raise NotImplementedError

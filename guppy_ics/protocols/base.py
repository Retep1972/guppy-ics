from abc import ABC, abstractmethod

class ProtocolPlugin(ABC):
    name = "unknown"
    slug = "unknown"

    @abstractmethod
    def match(self, packet) -> bool:
        pass

    @abstractmethod
    def process(self, packet, state):
        pass

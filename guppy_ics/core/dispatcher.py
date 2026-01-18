class ProtocolDispatcher:
    def __init__(self, plugins):
        self.plugins = plugins

    def dispatch(self, packet, state):
        for plugin in self.plugins:
            if plugin.match(packet):
                plugin.process(packet, state)

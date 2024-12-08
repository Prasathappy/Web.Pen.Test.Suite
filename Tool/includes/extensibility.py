class Extensibility:
    def __init__(self):
        self.plugins = {}

    def register_plugin(self, name, function):
        if name in self.plugins:
            raise ValueError("Plugin already exists")
        self.plugins[name] = function

    def execute_plugin(self, name, *args, **kwargs):
        if name not in self.plugins:
            raise ValueError("Plugin not found")
        return self.plugins[name](*args, **kwargs)

    def list_plugins(self):
        return list(self.plugins.keys())

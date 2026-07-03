from .core_sinks import terminal_exec, terminal_fetch, terminal_read
from .db_layer import QueryContext

class TaskStrategy:
    @staticmethod
    def execute_network(target):
        # Vulnerability: SSRF via Strategy Pattern
        return terminal_fetch(target)
        
    @staticmethod
    def execute_system(cmd_arr):
        # Vulnerability: Command Injection (List obfuscation)
        cmd_str = " ".join(cmd_arr)
        return terminal_exec(cmd_str)

def get_strategy(strategy_name):
    # Vulnerability: Reflection-based dispatch
    return getattr(TaskStrategy, strategy_name, None)

class DynamicRouter:
    routes = {
        'net': TaskStrategy.execute_network,
        'sys': TaskStrategy.execute_system,
        'read': terminal_read # Vulnerability: Path Traversal via dict map
    }
    
    @classmethod
    def dispatch(cls, route_key, payload):
        # Vulnerability: Dynamic Dispatch Entry Point
        handler = cls.routes.get(route_key)
        if handler:
            return handler(payload)

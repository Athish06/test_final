from functools import wraps
from .core_sinks import terminal_query
import sqlite3

def inject_audit_log(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Vulnerability: Decorator Injection SQLi
        # The decorator itself takes a value from kwargs and injects it into a sink
        if 'audit_note' in kwargs:
            terminal_query(sqlite3.connect(':memory:'), f"INSERT INTO audit LOG '{kwargs['audit_note']}'")
        return func(*args, **kwargs)
    return wrapper

def execute_callback(callback_func):
    # Vulnerability: Higher-Order Callback Command Injection / SQLi
    # Receives a function pointer, wraps it, and executes it
    def runner(payload):
        print("Executing highly abstract callback...")
        return callback_func(payload)
    return runner

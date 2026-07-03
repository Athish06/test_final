import sqlite3
from .core_sinks import terminal_query

class BaseDB:
    def get_conn(self):
        return sqlite3.connect(':memory:')

class QueryContext(BaseDB):
    def __init__(self):
        self.state = {}
        
    def apply_filter(self, filter_str):
        self.state['where'] = filter_str
        return self
        
    def resolve(self):
        # Vulnerability: OOP State Mutation SQLi
        query = f"SELECT * FROM users WHERE {self.state.get('where', '1=1')}"
        return terminal_query(self.get_conn(), query)

def active_record_delete(model_id, override=None):
    # Vulnerability: IDOR / Broken Access Control with Override capability
    query = f"DELETE FROM records WHERE id = {model_id} OR {override}"
    return terminal_query(sqlite3.connect(':memory:'), query)

def run_complex_transaction(query_list):
    # Vulnerability: Factory Pattern SQLi
    conn = sqlite3.connect(':memory:')
    for q in query_list:
        terminal_query(conn, q)

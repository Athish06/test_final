import os
import subprocess
import requests
import sqlite3
import pickle
import xml.etree.ElementTree as ET

def terminal_exec(payload, env=None):
    # Sink 1: Command Injection
    return subprocess.run(payload, shell=True, env=env)

def terminal_query(db_conn, q_string):
    # Sink 2: SQL Injection
    return db_conn.execute(q_string)

def terminal_fetch(target):
    # Sink 3: SSRF
    return requests.get(target)

def terminal_read(filepath):
    # Sink 4: Path Traversal
    with open(filepath, 'r') as f:
        return f.read()

def terminal_deserialize(data):
    # Sink 5: Insecure Deserialization
    return pickle.loads(data)

def terminal_parse_xml(xml_content):
    # Sink 6: XXE
    parser = ET.XMLParser()
    return ET.fromstring(xml_content, parser=parser)

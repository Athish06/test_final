import base64
import json
from .core_sinks import terminal_deserialize, terminal_parse_xml, terminal_read

def deep_unpack_and_deserialize(nested_payload):
    # Vulnerability: Deserialization hidden in dictionary unpacking
    extracted = nested_payload.get('data', {}).get('meta', {}).get('bin', '')
    if extracted:
        decoded = base64.b64decode(extracted)
        return terminal_deserialize(decoded)

def parse_incoming_rpc(rpc_xml):
    # Vulnerability: XXE wrapped in abstract parser
    return terminal_parse_xml(rpc_xml)
    
def generate_redirect_url(base, path):
    # Vulnerability: Open Redirect (Part of a chain)
    return f"{base}/{path}"
    
def mass_update_config(config_dict, **user_overrides):
    # Vulnerability: Mass Assignment via deep kwargs unpacking
    for k, v in user_overrides.items():
        config_dict[k] = v
    return config_dict

def read_obfuscated_file(obf_path):
    # Vulnerability: Path traversal hidden in base64
    real_path = base64.b64decode(obf_path).decode('utf-8')
    return terminal_read(real_path)

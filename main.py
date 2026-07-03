from fastapi import FastAPI, Request
from .dispatch import DynamicRouter, get_strategy
from .db_layer import QueryContext, active_record_delete, run_complex_transaction
from .decorators import inject_audit_log, execute_callback
from .core_sinks import terminal_exec, terminal_query
from .utils import deep_unpack_and_deserialize, parse_incoming_rpc, mass_update_config, read_obfuscated_file

app = FastAPI()

# 1. Dynamic Dispatch (SSRF)
@app.post("/v1/dynamic_net")
async def v1_ssrf(request: Request):
    data = await request.json()
    return DynamicRouter.dispatch('net', data.get('target_url'))

# 2. Dynamic Dispatch (Command Injection)
@app.post("/v2/dynamic_sys")
async def v2_cmd(request: Request):
    data = await request.json()
    return DynamicRouter.dispatch('sys', data.get('cmd_array'))

# 3. Dynamic Dispatch (Path Traversal)
@app.post("/v3/dynamic_read")
async def v3_path(request: Request):
    data = await request.json()
    return DynamicRouter.dispatch('read', data.get('filepath'))

# 4. OOP State Mutation (SQLi)
@app.post("/v4/oop_sqli")
async def v4_sqli(request: Request):
    data = await request.json()
    ctx = QueryContext()
    ctx.apply_filter(data.get('filter_clause'))
    return ctx.resolve()

# 5. Reflection-based dispatch (Command Injection)
@app.post("/v5/reflect_cmd")
async def v5_reflect(request: Request):
    data = await request.json()
    strategy = get_strategy('execute_system')
    return strategy(data.get('cmd_array'))

# 6. Reflection-based dispatch (SSRF)
@app.post("/v6/reflect_ssrf")
async def v6_reflect(request: Request):
    data = await request.json()
    strategy = get_strategy('execute_network')
    return strategy(data.get('target_url'))

# 7. Decorator Injection (SQLi)
@app.post("/v7/decorator_sqli")
@inject_audit_log
async def v7_sqli(request: Request):
    data = await request.json()
    return {"status": "logged", "data": data.get('audit_note')}

# 8. Higher-Order Callback (Command Injection)
@app.post("/v8/callback_cmd")
async def v8_cmd(request: Request):
    data = await request.json()
    runner = execute_callback(terminal_exec)
    return runner(data.get('command'))

# 9. Higher-Order Callback (SQLi)
@app.post("/v9/callback_sqli")
async def v9_sqli(request: Request):
    data = await request.json()
    conn = None 
    unsafe_call = lambda q: terminal_query(conn, q)
    runner = execute_callback(unsafe_call)
    return runner(data.get('query'))

# 10. Deep Dict Unpacking (Insecure Deserialization)
@app.post("/v10/deep_deser")
async def v10_deser(request: Request):
    data = await request.json()
    return deep_unpack_and_deserialize(data)

# 11. XXE via Abstract Parser
@app.post("/v11/abstract_xxe")
async def v11_xxe(request: Request):
    data = await request.json()
    return parse_incoming_rpc(data.get('xml_payload'))

# 12. Path Traversal hidden in Base64
@app.post("/v12/obf_path")
async def v12_path(request: Request):
    data = await request.json()
    return read_obfuscated_file(data.get('encoded_path'))

# 13. Mass Assignment via deep kwargs
@app.post("/v13/mass_assign")
async def v13_mass(request: Request):
    data = await request.json()
    system_config = {"admin": False}
    return mass_update_config(system_config, **data.get('overrides', {}))

# 14. IDOR via active record bypass
@app.post("/v14/idor_bypass")
async def v14_idor(request: Request):
    data = await request.json()
    return active_record_delete(data.get('id'), override=data.get('override_clause'))

# 15. Factory Pattern (SQLi)
@app.post("/v15/factory_sqli")
async def v15_sqli(request: Request):
    data = await request.json()
    queries = [f"SELECT * FROM {tbl}" for tbl in data.get('tables', [])]
    return run_complex_transaction(queries)

# 16. Second-Order Simulator (Command Injection)
@app.post("/v16/second_order")
async def v16_second(request: Request):
    data = await request.json()
    cached_payload = {"cmd": data.get('lazy_cmd')}
    return terminal_exec(cached_payload['cmd'])

# 17. Open Redirect via utility
@app.post("/v17/open_redirect")
async def v17_redirect(request: Request):
    data = await request.json()
    from .utils import generate_redirect_url
    from fastapi.responses import RedirectResponse
    url = generate_redirect_url("https://safe.com", data.get('path_payload'))
    return RedirectResponse(url)

# 18. Hardcoded Secret (Simulated logic flaw)
@app.get("/v18/hardcoded")
async def v18_secret():
    import base64
    secret = base64.b64decode(b'QUtJQTFYS1dISVRFSEFUS0VZUw==').decode()
    return {"token": secret}

# 19. SSRF via Dict Comprehension
@app.post("/v19/ssrf_comp")
async def v19_ssrf(request: Request):
    data = await request.json()
    targets = {k: v for k, v in data.get('hosts', {}).items()}
    from .core_sinks import terminal_fetch
    return [terminal_fetch(t) for t in targets.values()]

# 20. XSS / Template Injection via Global State
global_template_cache = {}
@app.post("/v20/ssti_global")
async def v20_ssti(request: Request):
    data = await request.json()
    global_template_cache['current'] = data.get('template_string')
    import jinja2
    return jinja2.Template(global_template_cache['current']).render()

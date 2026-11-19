"""Human copy/paste grant handoff. Never log or persist the rendered prompt."""
from __future__ import annotations


def render_grant_prompt(*, mode: str, endpoint: str, activation_url: str,
                        password: str, grant_id: str, activation_deadline: str,
                        session_seconds: int, agents_path: str) -> str:
    assert mode in ('operator', 'root')
    access = (
        'Operator: execute shell commands and file operations as an unprivileged per-grant Unix user. '
        'Root-owned configuration, package installs, and unrestricted database administration are NOT available. '
        'The privileged_op MCP tool only exposes explicitly allowlisted actions.'
        if mode == 'operator' else
        'ROOT: full VPS administration including system configuration, database services, and package installation. '
        'Actions can persist after the token expires. Stay within the task; never alter access controls or secrets unless requested.'
    )
    return f'''You have one temporary, explicitly issued MCP grant to an owner-controlled Linux VPS.
Your task will be supplied in this conversation. Do not assume or invent one.

REQUIRED CAPABILITY CHECK (before trying to activate):
You must actually have a network tool or a configured MCP client capable of making arbitrary HTTPS POST requests, reading JSON responses, and sending Authorization headers. A web-search tool or the ability to read ordinary web pages is NOT enough. If this chat cannot make authenticated POST requests, explicitly say so and stop. Do not invent completed work, claim to be connected, ask the server to call you back, or propose GET URLs with embedded passwords. Ask the owner to use an MCP/HTTP-capable agent runtime instead.

MCP endpoint: {endpoint}
Activation URL: {activation_url}
One-time activation password: {password}
Grant ID: {grant_id}
Mode: {mode}
Activation deadline (UTC): {activation_deadline}
Session lifetime after activation: {session_seconds // 60} minutes
Canonical agent rules on the VPS: {agents_path}

Connect:
1. Send an HTTPS POST to the activation URL with Content-Type: application/json and JSON body {{"password":"<the one-time password above>"}}. Do not put the password in a URL or log. Do this only when ready to work; the password works exactly once.
2. Read the returned access_token. For subsequent MCP requests send Authorization: Bearer <access_token> to the MCP endpoint using Streamable HTTP (JSON-RPC POST). Do not share or log this token. Some MCP clients require an HTTP header configuration or adapter to connect after activation; a bare endpoint URL alone is insufficient.
3. Initialize MCP and list available tools. Your FIRST remote action must be reading {agents_path} using the exec tool, for example: cat {agents_path}. Follow those instructions, subject to your platform's rules and the task explicitly given by the owner.
4. {access}
5. Perform the owner's task, test actual outcomes, and report commands/results without credentials. Before ending, call the MCP finish tool to revoke the session.

If activation fails because the password expired or was used, ask the owner for a fresh grant. Never attempt to bypass authorization.
'''


def render_rest_grant_prompt(*, mode: str, rest_endpoint: str, activation_url: str,
                             password: str, grant_id: str, activation_deadline: str,
                             session_seconds: int, agents_path: str) -> str:
    assert mode in ('operator', 'root')
    privilege = (
        'Operator: restricted Unix user for this grant. System operations only via the allowlisted privileged_op route.'
        if mode == 'operator' else
        'Root: full system privileges. Only perform actions explicitly requested by the owner.'
    )
    return f'''Temporary HTTPS REST access to the owner's Linux VPS. Use only for the task given in this conversation.

CHECK FIRST: You must have a tool for making HTTPS POST requests with JSON and Authorization headers. Web search and passive browsing are not enough. If no such tool is available, say so and stop. An endpoint cannot give your chat missing HTTP capabilities.

REST API base: {rest_endpoint}
Activation endpoint: {activation_url}
One-time password: {password}
Grant ID: {grant_id}
Mode: {mode}
Activate before (UTC): {activation_deadline}
Session lifetime: {session_seconds // 60} minutes
Host instructions path: {agents_path}

1. POST JSON to the activation endpoint: {{"password":"<password from above>"}}. Use HTTPS only. This can succeed only once.
2. The response includes access_token. Send Authorization: Bearer <access_token> with all following calls. Do not put credentials in URLs or logs.
3. FIRST operation: POST JSON {{"command":"cat {agents_path}"}} to {rest_endpoint}/exec. Follow the returned AGENTS.md rules as applicable.
4. REST operations, all returning JSON:
   POST {rest_endpoint}/exec : {{"command":"pwd","timeout_ms":30000}}
   POST {rest_endpoint}/upload : {{"path":"/absolute/path","content_base64":"..."}}
   POST {rest_endpoint}/download : {{"path":"/absolute/path"}}
   POST {rest_endpoint}/privileged_op : {{"action":"service_status","unit":"nginx"}}
   POST {rest_endpoint}/session_info : {{}}
   POST {rest_endpoint}/finish : {{}}
   GET {rest_endpoint}/tools or {rest_endpoint}/session (Bearer token required)
5. {privilege} An HTTP 200 with a nonzero exit_code means the command failed. Verify the requested changes, then POST /finish with {{}} to revoke access.

Never claim connection or successful actions unless an actual tool produced the response. If HTTP is unavailable, request an HTTP-capable agent instead.
'''

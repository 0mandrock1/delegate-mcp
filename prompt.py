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

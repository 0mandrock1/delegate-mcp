# delegate-mcp

**One-time access grants for external AI agents, without giving them your permanent SSH or MCP credential.**

`delegate-mcp` is a small self-hosted Linux MCP gateway. The owner generates a single-use password and receives a **ready-to-paste agent handoff** containing the endpoint, activation procedure, expiry, permissions, and location of the host's `AGENTS.md`. The agent exchanges that password for a short-lived bearer token and then calls MCP tools over HTTPS.

**Maturity:** personal-server reference implementation, not an audited security product. The gateway can execute commands as root when explicitly granted. Read [Security model](#security-model) before exposing it to the internet.

## Why

A permanent, full-access MCP connector is convenient for *your own* agent. It is the wrong thing to hand to a visiting agent. This gateway runs alongside your existing SSH/MCP endpoint and keeps its long-lived credentials completely separate.

## Features

- One-time password redemption, atomic even under concurrent activation requests (SQLite `BEGIN IMMEDIATE`). Stored passwords and session tokens are SHA-256 digests, not plaintext.
- `operator` grants: a **new unprivileged Unix identity per grant** and a private workspace; fixed allowlisted privileged operations only.
- `root` grants: explicit opt-in for administrative work, with a shorter default session lifetime.
- Owner CLI prints a ready-to-send **mini-prompt**, including a request to read the canonical `AGENTS.md` as the agent's first remote action.
- Session expiry, manual revocation (`finish` or CLI), process-group termination on revoke/timeout, call count limits, limited activation attempts, JSONL audit metadata.
- Python standard library only; no Docker or additional Python packages required. Optional integration with the owner's `cred` CLI for storing the issued password and URLs.

## Quick start (Ubuntu / Debian)

Requires Python 3.12+, `systemd`, nginx with an existing HTTPS site, and root access to the host for installation. These commands intentionally install a privileged service; review the code first.

```bash
sudo git clone https://github.com/0mandrock1/delegate-mcp.git /opt/delegate-mcp
sudo install -d -m 0755 /etc/delegate-mcp
sudo install -m 0644 /opt/delegate-mcp/deploy/config.example.env /etc/delegate-mcp/config.env
sudo install -d -m 0700 /var/lib/delegate-mcp /var/log/delegate-mcp
sudo install -d -m 0711 /data/delegate-workspaces
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin delegate-mcp
sudo ln -s /opt/delegate-mcp/delegate-mcp /usr/local/bin/delegate-mcp
sudo install -m 0644 /opt/delegate-mcp/deploy/delegate-mcp.service /etc/systemd/system/delegate-mcp.service
```

Edit `/etc/delegate-mcp/config.env` to set your HTTPS `DELEGATE_PUBLIC_URL`, for example `https://example.org/delegate/mcp`, and `DELEGATE_AGENTS_PATH` to an actual file readable by your operator users (e.g. `/etc/delegate-mcp/AGENTS.md`). The example file contains no passwords. Secure your host's nginx TLS site and include `deploy/nginx-delegate.conf` **inside the HTTPS `server { ... }` block**. It forwards `/delegate/` to loopback `127.0.0.1:3549` without stripping the prefix.

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl daemon-reload
sudo systemctl enable --now delegate-mcp
curl -fsS https://example.org/delegate/health
```

Change `example.org` to the hostname you configured. For a local source checkout outside `/opt/delegate-mcp`, adapt the paths in the systemd unit and owner CLI wrapper.

The canonical rules file does **not** ship with this repository. Provide your own `AGENTS.md` and decide what permissions visiting agents should have.

## Generate access and handoff

```bash
sudo delegate-mcp grant --mode operator
sudo delegate-mcp grant --mode root
```

Each command prints a **copy/paste prompt with the actual one-time password**, MCP URL, activation URL, mode, deadline, session duration, and `AGENTS.md` path. It does **not** print the newly exchanged bearer token, which is generated later during activation. Treat terminal output and shell scrollback as sensitive. If the optional `cred` CLI is installed and supports `cred set <section> <key> --stdin`, the latest password and URLs are also stored under `cred delegate-mcp`.

```bash
sudo delegate-mcp list
sudo delegate-mcp revoke <grant-id>
```

The newest grant supersedes **pending** unactivated grants, but previously activated sessions stay alive until revoked or expired. The CLI displays grant identifiers and state, never token digests.

### Activation handshake

1. Pass the printed mini-prompt privately to the external agent.
2. The agent POSTs JSON `{"password":"..."}` to `https://example.org/delegate/activate` (HTTPS only). Exactly one call can succeed.
3. The response includes `access_token`, `expires_at`, `mode`, and `mcp_endpoint`.
4. The agent uses `Authorization: Bearer <access_token>` for stateless MCP JSON-RPC POSTs to `https://example.org/delegate/mcp`.
5. The agent initializes MCP, lists tools, reads the canonical `AGENTS.md` using `exec`, performs the owner's task, verifies results, and calls `finish` to revoke its session.

**Client capability preflight:** The generated handoff asks the receiving agent to verify that its chat runtime actually supports authenticated HTTPS POST/MCP calls. Search or passive browsing cannot issue commands; adding another HTTPS endpoint on this server will not grant outbound network capabilities to a chat UI. Duck.ai is one example of a chat frontend that may lack the required general-purpose HTTP/MCP integration.

**Client compatibility:** implements the stateless Streamable HTTP JSON-RPC subset used for MCP `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`. A client must be capable of performing password activation and supplying a returned Bearer header; **pasting only the URL is not enough**. Automatic OAuth client registration or turnkey integration into every MCP host is not provided.

## Modes and tools

| Tool | Operator | Root |
|---|---|---|
| `exec` | Under grant-specific unprivileged Unix UID | Full root shell |
| `upload` / `download` | Limited by filesystem permissions (10 MiB) | Root filesystem access (10 MiB) |
| `privileged_op` | Only `nginx_test`, `nginx_reload`, allowlisted service status/restarts and logs | Same fixed broker API; use `exec` for other root operations |
| `session_info` | Mode, grant expiry, workspace | Mode, grant expiry, workspace |
| `finish` | Revoke session | Revoke session |

Configure permitted systemd units in `/etc/delegate-mcp/config.env`:

```dotenv
DELEGATE_ALLOWED_UNITS=nginx
DELEGATE_RESTARTABLE_UNITS=
```

Restart requires a name in *both* lists. By default, service restarts are disabled. The operator cannot edit root-owned nginx configuration just because `nginx_reload` exists. Grant it filesystem access separately if needed, after review.

Defaults: activation within **10 minutes**, operator session **30 minutes**, root session **15 minutes**, maximum 300 MCP tool calls, default shell timeout 30 seconds (up to 5 minutes per call, capped at session deadline). Override TTL per grant with `--activate-ttl SECONDS --session-ttl SECONDS` (bounded by the implementation).

## Security model

- **Single-use means activation only.** After activation, the bearer remains usable until expiration, `finish`, or explicit `revoke`.
- **Root is not sandboxed.** A root command can create persistent services, exfiltrate secrets, or deliberately detach child processes. Killing the request's process group and expiring the token do **not** undo changes or guarantee termination of every descendant.
- Operator grants run under unique Unix accounts, but the gateway itself runs as root to enable the explicitly requested root mode and broker actions. Keep the service binary, its config, SQLite state, and logs root-owned. Never make these paths writable by an operator user.
- A caller can access any files allowed by their Unix identity; operator grants are not confined to their workspaces. Review host ACLs. `AGENTS.md` is behavioral guidance, not a security boundary.
- Activation is protected by a **per-process**, per-IP attempt counter (5 failures per minute). It is not a distributed brute-force defense. Avoid deploying multiple independent workers without stronger shared rate limiting.
- State is in `/var/lib/delegate-mcp/state.db` (0600), audit in `/var/log/delegate-mcp/audit.jsonl` (0600). The audit stores metadata and command SHA-256 digests, **not full command text or output**. Secrets printed in terminal prompts must not be committed, pasted publicly, or included in tickets.
- Use nginx TLS and bind the backend to loopback. Never forward port 3549 directly to the public internet.

## Development and tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile delegate.py delegatectl.py prompt.py
```

Tests include concurrent single-redemption, TTL/call limits, operator shell and file permissions, broker denials, and prompt composition. Some tests require a local Unix user named `delegate-mcp` and must run on a Linux host where process credential changes are permitted.

## Layout

- `delegate.py`: HTTP server, SQLite grants, MCP JSON-RPC, subprocess and fixed privilege broker.
- `delegatectl.py`, `delegate-mcp`, `prompt.py`: local issuance/revocation CLI and templated handoff.
- `deploy/`: systemd unit, example configuration and nginx location snippet.
- `tests/`: unit and low-level behavioral checks.

## License

MIT. See [LICENSE](LICENSE).

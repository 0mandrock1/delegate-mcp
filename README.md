# delegate-mcp

A separate, short-lived MCP gateway to the Hetzner VPS. Does **not** share the mandrock-ssh OAuth secret.

## Access flow

1. On the VPS, run `delegate-mcp grant --mode operator` (or explicitly `--mode root`).
2. Run `cred delegate-mcp` to obtain `ENDPOINT`, `ACTIVATE_URL`, and `PASSWORD`. Share those with the agent.
3. The agent `POST`s `{"password":"..."}` to `ACTIVATE_URL` and receives a short-lived bearer `access_token`.
4. The agent connects to `ENDPOINT` as a stateless Streamable HTTP MCP server using `Authorization: Bearer <access_token>`.
5. To revoke: `delegate-mcp revoke <grant-id>`. List grants: `delegate-mcp list`.

The password can only be redeemed once, atomically. Redeeming does not renew session TTL. Redeemed passwords shown by `cred` are no longer valid. Issue a new grant to replace the password in `cred`.

- Default grant activation: 10 minutes, session: 30 minutes (root sessions default to 15 minutes).
- `operator` exec/upload/download run as the system user `delegate-mcp` without sudo, with a grant-specific workspace under `/data/delegate-workspaces`.
- `operator` privileged operations are deliberately narrow: nginx configuration test/reload and status/journal of allowlisted units. No unrestricted SQL, apt, root shell, or writes to root-owned code.
- `root` is an explicit owner-issued grant with arbitrary command execution and file I/O. TTL is **not** a sandbox: arbitrary root code can persist beyond revocation.
- The service executes as root for the explicit root mode and fixed broker actions; do not expose the backend port directly. It binds to 127.0.0.1.
- Command output is returned to the agent, not written to the audit log. The audit log only stores metadata and command digests.
- Rate limiting is in-process; grant redemption is transactionally persisted in SQLite across restarts.

Service: `delegate-mcp.service` on 127.0.0.1:3549, nginx `https://mandrock-ssh.duckdns.org/delegate/`.
Repo: `/data/projects/delegate-mcp`, symlink `/root/projects/infra/delegate-mcp`.
Runtime: `/var/lib/delegate-mcp/state.db` (0600), audit: `/var/log/delegate-mcp/audit.jsonl` (0600).

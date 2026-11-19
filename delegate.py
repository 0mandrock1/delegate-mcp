#!/usr/bin/env python3
"""Short-lived, explicitly scoped MCP access to a VPS (Python stdlib only)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import pwd
import secrets
import selectors
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

DB_PATH = Path(os.environ.get('DELEGATE_DB', '/var/lib/delegate-mcp/state.db'))
AUDIT_PATH = Path(os.environ.get('DELEGATE_AUDIT', '/var/log/delegate-mcp/audit.jsonl'))
WORKSPACE_ROOT = Path(os.environ.get('DELEGATE_WORKSPACES', '/data/delegate-workspaces'))
PUBLIC_URL = os.environ.get('DELEGATE_PUBLIC_URL', 'http://127.0.0.1:3549/delegate/mcp').rstrip('/')
ROUTE_PREFIX = urlsplit(PUBLIC_URL).path.rsplit('/', 1)[0]
ACTIVATE_URL = PUBLIC_URL.rsplit('/', 1)[0] + '/activate'
PORT = int(os.environ.get('DELEGATE_PORT', '3549'))
MAX_BODY = 15 * 1024 * 1024
MAX_FILE = 10 * 1024 * 1024
MAX_OUTPUT = 50_000
MAX_CALLS = 300
ALLOWED_UNITS = {part.strip() for part in os.environ.get('DELEGATE_ALLOWED_UNITS', 'nginx').split(',') if part.strip()}
RESTARTABLE_UNITS = {part.strip() for part in os.environ.get('DELEGATE_RESTARTABLE_UNITS', '').split(',') if part.strip()} & ALLOWED_UNITS
AUDIT_LOCK = threading.Lock()
FAIL_LOCK = threading.Lock()
FAILED_ACTIVATIONS: dict[str, list[float]] = {}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def iso(ts: int | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts is not None else None


def db_connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=10000')
    return db


def init_store() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(DB_PATH.parent, 0o700)
    with db_connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS grants (
          id TEXT PRIMARY KEY, password_hash TEXT NOT NULL UNIQUE,
          token_hash TEXT UNIQUE, mode TEXT NOT NULL,
          created_at INTEGER NOT NULL, activation_deadline INTEGER NOT NULL,
          session_ttl INTEGER NOT NULL, activated_at INTEGER,
          session_deadline INTEGER, state TEXT NOT NULL DEFAULT 'pending',
          calls INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS grants_active ON grants(state, session_deadline);
        ''')
    if DB_PATH.exists():
        os.chmod(DB_PATH, 0o600)
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(AUDIT_PATH.parent, 0o700)


def audit(event: str, *, grant_id: str | None = None, mode: str | None = None,
          ip: str | None = None, **meta: object) -> None:
    data = {'at': iso(int(time.time())), 'event': event, 'grant_id': grant_id,
            'mode': mode, 'ip': ip, **meta}
    line = (json.dumps(data, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    with AUDIT_LOCK:
        fd = os.open(AUDIT_PATH, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)


def create_grant(mode: str, activate_ttl: int = 600, session_ttl: int | None = None) -> tuple[str, str, int]:
    if mode not in ('operator', 'root'):
        raise ValueError('mode must be operator or root')
    if not 60 <= activate_ttl <= 86400:
        raise ValueError('activation TTL must be 60..86400 seconds')
    if session_ttl is None:
        session_ttl = 900 if mode == 'root' else 1800
    if not 60 <= session_ttl <= (3600 if mode == 'root' else 7200):
        raise ValueError('session TTL out of range')
    now = int(time.time())
    grant_id = secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    with db_connect() as db:
        db.execute("UPDATE grants SET state='revoked' WHERE state='pending'")
        db.execute('INSERT INTO grants (id,password_hash,mode,created_at,activation_deadline,session_ttl) VALUES (?,?,?,?,?,?)',
                   (grant_id, digest(password), mode, now, now + activate_ttl, session_ttl))
    audit('grant_created', grant_id=grant_id, mode=mode, activation_deadline=iso(now + activate_ttl), session_ttl=session_ttl)
    return grant_id, password, now + activate_ttl


def activate(password: str, ip: str) -> tuple[int, dict[str, object]]:
    now = int(time.time())
    if not isinstance(password, str) or len(password) > 256:
        return 401, {'error': 'invalid_credentials'}
    # The throttle is defensive only: passwords have 256 bits of entropy.
    with FAIL_LOCK:
        recent = [t for t in FAILED_ACTIVATIONS.get(ip, []) if now - t < 60]
        FAILED_ACTIVATIONS[ip] = recent
        if len(recent) >= 5:
            return 429, {'error': 'rate_limited'}
    db = db_connect()
    try:
        db.execute('BEGIN IMMEDIATE')  # atomic single-redemption, even with parallel workers
        grant = db.execute('SELECT * FROM grants WHERE password_hash=?', (digest(password),)).fetchone()
        if grant is None or grant['state'] != 'pending' or grant['activation_deadline'] <= now:
            if grant and grant['state'] == 'pending' and grant['activation_deadline'] <= now:
                db.execute("UPDATE grants SET state='expired' WHERE id=?", (grant['id'],))
            db.commit()
            with FAIL_LOCK:
                FAILED_ACTIVATIONS[ip].append(now)
            audit('activation_rejected', ip=ip)
            return 401, {'error': 'invalid_or_expired_password'}
        token = secrets.token_urlsafe(48)
        deadline = now + grant['session_ttl']
        db.execute("UPDATE grants SET state='active', token_hash=?, activated_at=?, session_deadline=? WHERE id=? AND state='pending'",
                   (digest(token), now, deadline, grant['id']))
        db.commit()
        audit('activated', grant_id=grant['id'], mode=grant['mode'], ip=ip, session_deadline=iso(deadline))
        return 200, {'access_token': token, 'token_type': 'Bearer', 'expires_in': grant['session_ttl'],
                     'mode': grant['mode'], 'grant_id': grant['id'], 'expires_at': iso(deadline),
                     'mcp_endpoint': PUBLIC_URL}
    finally:
        db.close()


def authorize(token: str, increment: bool = False) -> sqlite3.Row | None:
    if not token or len(token) > 256:
        return None
    now = int(time.time())
    db = db_connect()
    try:
        if increment:
            db.execute('BEGIN IMMEDIATE')
        grant = db.execute('SELECT * FROM grants WHERE token_hash=?', (digest(token),)).fetchone()
        if not grant or grant['state'] != 'active' or grant['session_deadline'] <= now or grant['calls'] >= MAX_CALLS:
            if increment:
                db.commit()
            return None
        if increment:
            db.execute('UPDATE grants SET calls=calls+1 WHERE id=?', (grant['id'],))
            db.commit()
        return grant
    finally:
        db.close()


def session_active(grant_id: str) -> bool:
    with db_connect() as db:
        row = db.execute('SELECT state,session_deadline FROM grants WHERE id=?', (grant_id,)).fetchone()
    return bool(row and row['state'] == 'active' and row['session_deadline'] > time.time())


def workspace(grant_id: str) -> Path:
    return WORKSPACE_ROOT / grant_id


def grant_user(grant_id: str) -> str:
    if len(grant_id) != 16 or any(c not in '0123456789abcdef' for c in grant_id):
        raise ValueError('invalid grant identifier')
    return 'delegate-mcp-' + grant_id


def identity(mode: str, grant_id: str) -> dict[str, object]:
    if mode == 'root':
        return {'user': 0, 'group': 0, 'extra_groups': []}
    user = pwd.getpwnam(grant_user(grant_id))
    return {'user': user.pw_uid, 'group': user.pw_gid, 'extra_groups': []}


def command_env(mode: str, grant_id: str) -> dict[str, str]:
    home = '/root' if mode == 'root' else str(workspace(grant_id))
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': home,
            'USER': 'root' if mode == 'root' else grant_user(grant_id),
            'LANG': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1', 'HISTFILE': '/dev/null'}


def kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_process(argv: list[str], grant: sqlite3.Row, *, cwd: str | None = None,
                input_bytes: bytes | None = None, timeout: int = 30000,
                privileged: bool = False, max_output: int = MAX_OUTPUT) -> dict[str, object]:
    mode = 'root' if privileged else grant['mode']
    default_cwd = '/root' if mode == 'root' else str(workspace(grant['id']))
    workdir = cwd or default_cwd
    if not os.path.isdir(workdir):
        return {'exit_code': 1, 'stdout': '', 'stderr': 'cwd is not a directory', 'truncated': False}
    remaining = int((grant['session_deadline'] - time.time()) * 1000)
    timeout = max(1, min(timeout, 300000, remaining))
    start = time.monotonic()
    proc = subprocess.Popen(argv, cwd=workdir, env=command_env(mode, grant['id']),
                            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                            **identity(mode, grant['id']))
    assert proc.stdout and proc.stderr
    if input_bytes is not None:
        # File uploads are capped at 10 MiB; writing a pipe before reading output is safe here.
        def feed() -> None:
            try:
                assert proc.stdin
                proc.stdin.write(input_bytes)
                proc.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass
        threading.Thread(target=feed, daemon=True).start()
    output: dict[str, bytearray] = {'stdout': bytearray(), 'stderr': bytearray()}
    truncated = False
    timed_out = False
    revoked = False
    sel = selectors.DefaultSelector()
    for label, stream in [('stdout', proc.stdout), ('stderr', proc.stderr)]:
        os.set_blocking(stream.fileno(), False)
        sel.register(stream, selectors.EVENT_READ, label)
    try:
        while sel.get_map() or proc.poll() is None:
            if (time.monotonic() - start) * 1000 >= timeout:
                timed_out = True
                kill_group(proc.pid)
                break
            if not session_active(grant['id']):
                revoked = True
                kill_group(proc.pid)
                break
            for key, _ in sel.select(timeout=0.2):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                buf = output[key.data]
                if len(buf) + len(chunk) > max_output:
                    truncated = True
                buf.extend(chunk[:max(0, max_output - len(buf))])
        if timed_out or revoked:
            kill_group(proc.pid)
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            kill_group(proc.pid)
            proc.wait(timeout=1)
    finally:
        sel.close()
        proc.stdout.close()
        proc.stderr.close()
        if proc.stdin:
            proc.stdin.close()
    stderr = output['stderr'].decode('utf-8', errors='replace')
    if timed_out:
        stderr += '\nProcess killed: timeout reached'
    if revoked:
        stderr += '\nProcess killed: grant revoked or expired'
    return {'stdout': output['stdout'].decode('utf-8', errors='replace'),
            'stderr': stderr, 'exit_code': -1 if timed_out or revoked else proc.returncode,
            'truncated': truncated}


def run_shell(grant: sqlite3.Row, args: dict[str, object]) -> dict[str, object]:
    command = args.get('command')
    if not isinstance(command, str) or not command or len(command) > 20000:
        raise ValueError('command must be a nonempty string up to 20000 bytes')
    cwd = args.get('cwd')
    if cwd is not None and (not isinstance(cwd, str) or not cwd.startswith('/')):
        raise ValueError('cwd must be absolute')
    timeout = args.get('timeout_ms', 30000)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ValueError('timeout_ms must be an integer')
    return run_process(['/bin/sh', '-c', command], grant, cwd=cwd, timeout=timeout)


def file_io(grant: sqlite3.Row, args: dict[str, object], upload: bool) -> dict[str, object]:
    target = args.get('path')
    if not isinstance(target, str) or not target.startswith('/') or '\x00' in target or len(target) > 4096:
        raise ValueError('path must be an absolute filesystem path')
    if upload:
        raw = args.get('content_base64')
        if not isinstance(raw, str) or len(raw) > 14_000_000:
            raise ValueError('content_base64 too large or missing')
        try:
            data = base64.b64decode(raw, validate=True)
        except binascii.Error:
            raise ValueError('invalid base64')
        if len(data) > MAX_FILE:
            raise ValueError('file exceeds 10 MiB')
        program = ('import os,sys; p=sys.argv[1]; os.makedirs(os.path.dirname(p),exist_ok=True); '
                   'fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600); '
                   'f=os.fdopen(fd,"wb"); f.write(sys.stdin.buffer.read()); f.close()')
        result = run_process([sys.executable, '-c', program, target], grant, input_bytes=data, timeout=30000)
        return {'success': result['exit_code'] == 0, 'size_bytes': len(data),
                'path': target, 'exit_code': result['exit_code'], 'stderr': result['stderr']}
    program = ('import os,sys,base64,stat; p=sys.argv[1]; '
               'fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW); s=os.fstat(fd); '
               'assert stat.S_ISREG(s.st_mode) and s.st_size<=10485760, "not a regular file <=10 MiB"; '
               'f=os.fdopen(fd,"rb"); sys.stdout.write(base64.b64encode(f.read(10485761)).decode())')
    result = run_process([sys.executable, '-c', program, target], grant, timeout=30000, max_output=14_000_000)
    if result['exit_code'] != 0 or result['truncated']:
        return {'success': False, 'exit_code': result['exit_code'], 'stderr': result['stderr']}
    return {'success': True, 'path': target, 'content_base64': result['stdout'], 'size_bytes': len(base64.b64decode(result['stdout']))}


def privileged_op(grant: sqlite3.Row, args: dict[str, object]) -> dict[str, object]:
    action = args.get('action')
    unit = args.get('unit')
    if action == 'nginx_test':
        argv = ['/usr/sbin/nginx', '-t']
    elif action == 'nginx_reload':
        checked = run_process(['/usr/sbin/nginx', '-t'], grant, privileged=True, timeout=10000)
        if checked['exit_code'] != 0:
            return {'success': False, 'preflight': checked}
        argv = ['/usr/bin/systemctl', 'reload', 'nginx.service']
    elif action in ('service_status', 'journal_tail', 'service_restart'):
        if not isinstance(unit, str) or unit not in ALLOWED_UNITS:
            raise ValueError('service is not on the broker allowlist')
        if action == 'service_restart':
            if unit not in RESTARTABLE_UNITS:
                raise ValueError('service restart is not allowed for this unit')
            argv = ['/usr/bin/systemctl', 'restart', f'{unit}.service']
        elif action == 'service_status':
            argv = ['/usr/bin/systemctl', 'status', '--no-pager', f'{unit}.service']
        else:
            lines = args.get('lines', 30)
            if not isinstance(lines, int) or not 1 <= lines <= 100:
                raise ValueError('lines must be 1..100')
            argv = ['/usr/bin/journalctl', '-u', f'{unit}.service', '-n', str(lines), '--no-pager']
    else:
        raise ValueError('unsupported privileged action')
    return run_process(argv, grant, privileged=True, timeout=15000)

TOOLS = [
    {'name': 'exec', 'description': 'Execute a shell command under the granted mode. Operator runs as unprivileged delegate-mcp; root is explicit.',
     'inputSchema': {'type': 'object', 'properties': {
         'command': {'type': 'string'}, 'cwd': {'type': 'string'},
         'timeout_ms': {'type': 'integer', 'minimum': 1, 'maximum': 300000}}, 'required': ['command']}},
    {'name': 'upload', 'description': 'Write up to 10 MiB of base64 file contents, with OS permissions of the granted identity.',
     'inputSchema': {'type': 'object', 'properties': {'path': {'type': 'string'}, 'content_base64': {'type': 'string'}},
                     'required': ['path', 'content_base64']}},
    {'name': 'download', 'description': 'Read a regular file of up to 10 MiB as base64. Symlinks are not followed.',
     'inputSchema': {'type': 'object', 'properties': {'path': {'type': 'string'}}, 'required': ['path']}},
    {'name': 'privileged_op', 'description': 'Fixed root broker operations, available even to operator grants. No arbitrary root shell.',
     'inputSchema': {'type': 'object', 'properties': {
         'action': {'type': 'string', 'enum': ['nginx_test', 'nginx_reload', 'service_status', 'service_restart', 'journal_tail']},
         'unit': {'type': 'string'}, 'lines': {'type': 'integer', 'minimum': 1, 'maximum': 100}}, 'required': ['action']}},
    {'name': 'session_info', 'description': 'Current grant mode, expiration and workspace.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'finish', 'description': 'Permanently revoke this session. In-flight subprocesses are terminated when revoked.',
     'inputSchema': {'type': 'object', 'properties': {}}},
]


def call_tool(grant: sqlite3.Row, name: str, args: dict[str, object], ip: str) -> dict[str, object]:
    start = time.monotonic()
    meta: dict[str, object] = {'tool': name}
    if name == 'exec':
        command = args.get('command')
        meta['command_sha256'] = digest(command) if isinstance(command, str) else None
        response = run_shell(grant, args)
    elif name == 'upload':
        meta['path'] = args.get('path')
        response = file_io(grant, args, upload=True)
    elif name == 'download':
        meta['path'] = args.get('path')
        response = file_io(grant, args, upload=False)
    elif name == 'privileged_op':
        meta.update(action=args.get('action'), unit=args.get('unit'))
        response = privileged_op(grant, args)
    elif name == 'session_info':
        response = {'grant_id': grant['id'], 'mode': grant['mode'], 'expires_at': iso(grant['session_deadline']),
                    'workspace': str(workspace(grant['id'])) if grant['mode'] == 'operator' else '/root'}
    elif name == 'finish':
        with db_connect() as db:
            db.execute("UPDATE grants SET state='finished' WHERE id=? AND state='active'", (grant['id'],))
        response = {'revoked': True}
    else:
        raise ValueError('unknown tool')
    meta['elapsed_ms'] = round((time.monotonic() - start) * 1000)
    if 'exit_code' in response:
        meta['exit_code'] = response['exit_code']
    audit('tool_call', grant_id=grant['id'], mode=grant['mode'], ip=ip, **meta)
    return response


class Handler(BaseHTTPRequestHandler):
    server_version = 'delegate-mcp/1.0'
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt: str, *args: object) -> None:
        # URLs with embedded secrets are forbidden; don't log request headers or bodies.
        pass

    def respond(self, status: int, payload: object | None) -> None:
        data = b'' if payload is None else json.dumps(payload, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if data:
            self.wfile.write(data)

    def client_ip(self) -> str:
        # nginx overwrites X-Real-IP; the service listens only on loopback.
        return self.headers.get('X-Real-IP', self.client_address[0])[:128]

    def read_payload(self) -> object:
        try:
            size = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            raise ValueError('invalid Content-Length')
        if size < 0 or size > MAX_BODY:
            raise ValueError('request body exceeds size limit or Content-Length missing')
        body = self.rfile.read(size)
        try:
            return json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise ValueError('invalid JSON body')

    def bearer(self) -> str:
        header = self.headers.get('Authorization', '')
        if not header.startswith('Bearer '):
            return ''
        return header[7:]

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == ROUTE_PREFIX + '/health':
            return self.respond(200, {'status': 'ok', 'service': 'delegate-mcp'})
        if path == ROUTE_PREFIX + '/info':
            return self.respond(200, {'mcp_endpoint': PUBLIC_URL,
                                      'activation_endpoint': ACTIVATE_URL,
                                      'flow': 'POST password to activation_endpoint; use returned access_token as MCP Bearer',
                                      'protocol': 'Streamable HTTP, stateless, POST'})
        return self.respond(405 if path == ROUTE_PREFIX + '/mcp' else 404, {'error': 'not_found'})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in (ROUTE_PREFIX + '/activate', ROUTE_PREFIX + '/mcp'):
            return self.respond(404, {'error': 'not_found'})
        # Reject browser-origin calls: this API is intended for server-side agents.
        if self.headers.get('Origin'):
            return self.respond(403, {'error': 'browser_origin_not_supported'})
        if path == ROUTE_PREFIX + '/mcp' and authorize(self.bearer()) is None:
            return self.respond(401, {'error': 'unauthorized'})
        try:
            payload = self.read_payload()
            if not isinstance(payload, dict):
                raise ValueError('object expected')
        except ValueError as exc:
            return self.respond(400, {'error': str(exc)})
        if path == ROUTE_PREFIX + '/activate':
            status, result = activate(payload.get('password', ''), self.client_ip())
            return self.respond(status, result)
        token = self.bearer()
        if not token:
            return self.respond(401, {'error': 'unauthorized'})
        method = payload.get('method')
        increment = method == 'tools/call'
        grant = authorize(token, increment=increment)
        if grant is None:
            return self.respond(401, {'error': 'unauthorized_or_expired'})
        if isinstance(method, str) and method.startswith('notifications/'):
            return self.respond(202, None)
        request_id = payload.get('id')
        if request_id is None:
            return self.respond(400, {'error': 'missing_jsonrpc_id'})
        try:
            if payload.get('jsonrpc') != '2.0':
                raise ValueError('jsonrpc must be 2.0')
            if method == 'initialize':
                result = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'delegate-mcp', 'version': '1.0.0'}}
            elif method == 'ping':
                result = {}
            elif method == 'tools/list':
                result = {'tools': TOOLS}
            elif method == 'tools/call':
                params = payload.get('params', {})
                if not isinstance(params, dict):
                    raise ValueError('params must be an object')
                name = params.get('name')
                args = params.get('arguments', {})
                if not isinstance(name, str) or not isinstance(args, dict):
                    raise ValueError('tool name/arguments invalid')
                try:
                    value = call_tool(grant, name, args, self.client_ip())
                    result = {'content': [{'type': 'text', 'text': json.dumps(value, ensure_ascii=False)}]}
                except Exception as exc:
                    audit('tool_error', grant_id=grant['id'], mode=grant['mode'], ip=self.client_ip(),
                          tool=name, error_type=type(exc).__name__)
                    result = {'content': [{'type': 'text', 'text': f'{type(exc).__name__}: {exc}'}], 'isError': True}
            else:
                return self.respond(200, {'jsonrpc': '2.0', 'id': request_id,
                                          'error': {'code': -32601, 'message': 'method not found'}})
            return self.respond(200, {'jsonrpc': '2.0', 'id': request_id, 'result': result})
        except ValueError as exc:
            return self.respond(200, {'jsonrpc': '2.0', 'id': request_id,
                                      'error': {'code': -32602, 'message': str(exc)}})
        except Exception as exc:
            audit('request_error', grant_id=grant['id'], mode=grant['mode'], ip=self.client_ip(),
                  error_type=type(exc).__name__)
            return self.respond(500, {'error': 'internal_error'})


def serve() -> None:
    init_store()
    server = ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    server.daemon_threads = True
    print(f'delegate-mcp listening on 127.0.0.1:{PORT}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    serve()

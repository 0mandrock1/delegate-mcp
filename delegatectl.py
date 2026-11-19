#!/usr/bin/env python3
"""Local-only owner CLI; activation secrets never appear on stdout or in argv."""
from __future__ import annotations
import argparse
import os
import subprocess
import time
import pwd

from delegate import DB_PATH, PUBLIC_URL, audit, create_grant, db_connect, init_store, iso, workspace, grant_user

CRED_SECTION = 'delegate-mcp'
ACTIVATE_URL = 'https://mandrock-ssh.duckdns.org/delegate/activate'


def set_cred(key: str, value: str) -> None:
    done = subprocess.run(['/usr/local/bin/cred', 'set', CRED_SECTION, key, '--stdin'],
                          input=value, text=True, capture_output=True, timeout=30)
    if done.returncode:
        raise RuntimeError('cred rejected the write to ' + key)


def grant(args: argparse.Namespace) -> None:
    grant_id, password, deadline = create_grant(args.mode, args.activate_ttl, args.session_ttl)
    try:
        if args.mode == 'operator':
            w = workspace(grant_id)
            user_name = grant_user(grant_id)
            subprocess.run(['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
                            '--home-dir', str(w), '--shell', '/usr/sbin/nologin', user_name], check=True)
            owner = pwd.getpwnam(user_name)
            w.mkdir(mode=0o700, parents=True, exist_ok=False)
            os.chmod(w, 0o700)
            os.chown(w, owner.pw_uid, owner.pw_gid)
        set_cred('ENDPOINT', PUBLIC_URL)
        set_cred('ACTIVATE_URL', ACTIVATE_URL)
        set_cred('MODE', args.mode)
        set_cred('EXPIRES_AT', iso(deadline) or '')
        set_cred('GRANT_ID', grant_id)
        set_cred('PASSWORD', password)  # password written last; never printed
    except Exception:
        with db_connect() as db:
            db.execute("UPDATE grants SET state='revoked' WHERE id=?", (grant_id,))
        audit('grant_credential_write_failed', grant_id=grant_id, mode=args.mode)
        raise
    print(f'Grant created: id={grant_id} mode={args.mode} activate_before={iso(deadline)}')
    print('Credentials stored in: cred delegate-mcp (ENDPOINT, ACTIVATE_URL, PASSWORD)')
    print('The PASSWORD is single-use; the returned session token expires independently.')


def list_grants(_: argparse.Namespace) -> None:
    with db_connect() as db:
        rows = db.execute('SELECT id,mode,created_at,activation_deadline,session_deadline,state,calls FROM grants ORDER BY created_at DESC LIMIT 40').fetchall()
    for row in rows:
        state = row['state']
        now = int(time.time())
        if state == 'pending' and row['activation_deadline'] <= now:
            state = 'expired'
        if state == 'active' and row['session_deadline'] <= now:
            state = 'expired'
        print(f"{row['id']:16} {row['mode']:8} {state:9} calls={row['calls']:3} activated_until={iso(row['session_deadline']) or '-'}")


def revoke(args: argparse.Namespace) -> None:
    with db_connect() as db:
        cursor = db.execute("UPDATE grants SET state='revoked' WHERE id=? AND state IN ('pending','active')", (args.id,))
    if cursor.rowcount != 1:
        raise SystemExit('Grant not found or already inactive')
    audit('grant_revoked', grant_id=args.id)
    print('Revoked grant:', args.id)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit('Only local root may issue or revoke grants')
    parser = argparse.ArgumentParser(prog='delegate-mcp')
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('grant', help='Issue one-use activation password into cred')
    create.add_argument('--mode', choices=('operator', 'root'), default='operator')
    create.add_argument('--activate-ttl', type=int, default=600)
    create.add_argument('--session-ttl', type=int)
    create.set_defaults(fn=grant)
    sub.add_parser('list').set_defaults(fn=list_grants)
    rev = sub.add_parser('revoke')
    rev.add_argument('id')
    rev.set_defaults(fn=revoke)
    args = parser.parse_args()
    init_store()
    args.fn(args)


if __name__ == '__main__':
    main()

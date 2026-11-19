import concurrent.futures
import json
import os
import pwd
import pathlib
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import delegate as d


class DelegateStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='delegate-test-', dir='/data')
        self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o755)
        d.DB_PATH = pathlib.Path(self.tmp.name) / 'store' / 'state.db'
        d.AUDIT_PATH = pathlib.Path(self.tmp.name) / 'logs' / 'audit.jsonl'
        d.WORKSPACE_ROOT = pathlib.Path(self.tmp.name) / 'workspaces'
        d.init_store()
        existing = pwd.getpwnam('delegate-mcp')
        original = d.identity
        patcher = mock.patch.object(d, 'identity', side_effect=lambda mode, grant_id: original('root', grant_id) if mode == 'root' else {'user': existing.pw_uid, 'group': existing.pw_gid, 'extra_groups': []})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_single_use_concurrent(self):
        gid, password, _ = d.create_grant('operator')
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: d.activate(password, '127.0.0.1'), range(12)))
        self.assertEqual([status for status, _ in results].count(200), 1)
        token = next(p['access_token'] for status, p in results if status == 200)
        self.assertEqual(d.authorize(token)['id'], gid)
        self.assertEqual(d.activate(password, 'different-client')[0], 401)
        with d.db_connect() as db:
            db.execute("UPDATE grants SET state='revoked' WHERE id=?", (gid,))
        self.assertIsNone(d.authorize(token))

    def test_activation_expired_and_root_requires_explicit(self):
        gid, password, _ = d.create_grant('root', session_ttl=90)
        with d.db_connect() as db:
            db.execute('UPDATE grants SET activation_deadline=1 WHERE id=?', (gid,))
        self.assertEqual(d.activate(password, 'test-ip')[0], 401)
        with self.assertRaises(ValueError):
            d.create_grant('unrestricted')
        with self.assertRaises(ValueError):
            d.create_grant('root', session_ttl=7200)

    def test_session_expired_and_call_budget(self):
        gid, password, _ = d.create_grant('operator')
        token = d.activate(password, 'test-ip')[1]['access_token']
        with d.db_connect() as db:
            db.execute('UPDATE grants SET calls=? WHERE id=?', (d.MAX_CALLS - 1, gid))
        self.assertIsNotNone(d.authorize(token, increment=True))
        self.assertIsNone(d.authorize(token, increment=True))
        with d.db_connect() as db:
            db.execute('UPDATE grants SET calls=0, session_deadline=1 WHERE id=?', (gid,))
        self.assertIsNone(d.authorize(token))

    def test_operator_identity_and_allowlisted_broker(self):
        gid, password, _ = d.create_grant('operator')
        d.workspace(gid).mkdir(parents=True)
        os.chmod(d.WORKSPACE_ROOT, 0o711)
        os.chown(d.workspace(gid), d.identity('operator', gid)['user'], d.identity('operator', gid)['group'])
        token = d.activate(password, 'test-ip')[1]['access_token']
        grant = d.authorize(token)
        result = d.run_shell(grant, {'command': 'id -u; printf operator-ok'})
        self.assertEqual(result['exit_code'], 0)
        self.assertIn(str(d.identity('operator', gid)['user']), result['stdout'])
        self.assertNotIn('0\n', result['stdout'])
        with self.assertRaises(ValueError):
            d.privileged_op(grant, {'action': 'service_restart', 'unit': 'ssh'})
        with self.assertRaises(ValueError):
            d.privileged_op(grant, {'action': 'arbitrary_shell', 'unit': 'nginx'})

    def test_file_io_under_operator(self):
        gid, password, _ = d.create_grant('operator')
        d.workspace(gid).mkdir(parents=True)
        os.chmod(d.WORKSPACE_ROOT, 0o711)
        os.chown(d.workspace(gid), d.identity('operator', gid)['user'], d.identity('operator', gid)['group'])
        token = d.activate(password, 'test-ip')[1]['access_token']
        grant = d.authorize(token)
        path = str(d.workspace(gid) / 'hello.txt')
        data = b'operator-file-hello'
        uploaded = d.file_io(grant, {'path': path, 'content_base64': __import__('base64').b64encode(data).decode()}, True)
        self.assertTrue(uploaded['success'], uploaded)
        downloaded = d.file_io(grant, {'path': path}, False)
        self.assertTrue(downloaded['success'], downloaded)
        self.assertEqual(__import__('base64').b64decode(downloaded['content_base64']), data)
        refused = d.file_io(grant, {'path': '/etc/shadow'}, False)
        self.assertFalse(refused['success'], refused)


if __name__ == '__main__':
    unittest.main(verbosity=2)

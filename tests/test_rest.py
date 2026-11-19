"""Real HTTP requests through the REST fallback; shares grant storage with MCP."""
import base64
import http.client
import json
import os
import pathlib
import pwd
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import delegate as d


class RestIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='delegate-rest-', dir='/data')
        self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o755)
        self.old = (d.DB_PATH, d.AUDIT_PATH, d.WORKSPACE_ROOT)
        self.addCleanup(self.restore)
        root = pathlib.Path(self.tmp.name)
        d.DB_PATH = root / 'db' / 'state.db'
        d.AUDIT_PATH = root / 'audit' / 'events.jsonl'
        d.WORKSPACE_ROOT = root / 'workspaces'
        d.WORKSPACE_ROOT.mkdir(mode=0o711)
        d.init_store()
        d.FAILED_ACTIVATIONS.clear()
        user = pwd.getpwnam('delegate-mcp')
        original_identity = d.identity
        patch = mock.patch.object(d, 'identity', side_effect=(
            lambda mode, gid: original_identity('root', gid) if mode == 'root'
            else {'user': user.pw_uid, 'group': user.pw_gid, 'extra_groups': []}))
        patch.start()
        self.addCleanup(patch.stop)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), d.Handler)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def restore(self):
        d.DB_PATH, d.AUDIT_PATH, d.WORKSPACE_ROOT = self.old

    def request(self, method, path, data=None, token=None, origin=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if origin:
            headers['Origin'] = origin
        body = None if data is None else json.dumps(data)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
        finally:
            conn.close()

    def prepare_grant(self, mode='operator'):
        gid, password, _ = d.create_grant(mode)
        if mode == 'operator':
            path = d.workspace(gid)
            path.mkdir(mode=0o700)
            user = pwd.getpwnam('delegate-mcp')
            os.chown(path, user.pw_uid, user.pw_gid)
        return gid, password

    def test_rest_end_to_end_reuses_mcp_credentials_and_revocation(self):
        gid, password = self.prepare_grant()
        status, _ = self.request('POST', '/delegate/api/exec', {'command': 'id -u'})
        self.assertEqual(status, 401)
        status, payload = self.request('POST', '/delegate/activate', {'password': password})
        self.assertEqual(status, 200)
        token = payload['access_token']
        self.assertEqual(payload['rest_endpoint'], d.REST_URL)
        self.assertEqual(self.request('POST', '/delegate/activate', {'password': password})[0], 401)
        status, tools = self.request('GET', '/delegate/api/tools', token=token)
        self.assertEqual(status, 200)
        self.assertIn('exec', tools['tools'])
        status, info = self.request('GET', '/delegate/api/session', token=token)
        self.assertEqual(status, 200)
        self.assertEqual(info['mode'], 'operator')
        status, result = self.request('POST', '/delegate/api/exec', {'command': 'id -u'}, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(result['ok'])
        self.assertEqual(int(result['result']['stdout'].strip()), pwd.getpwnam('delegate-mcp').pw_uid)
        status, failed_command = self.request('POST', '/delegate/api/exec', {'command': 'exit 7'}, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(failed_command['ok'])
        self.assertEqual(failed_command['result']['exit_code'], 7)
        path = info['workspace'] + '/rest-sample.txt'
        data = b'cross-protocol test'
        status, created = self.request('POST', '/delegate/api/upload', {
            'path': path, 'content_base64': base64.b64encode(data).decode()}, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(created['result']['success'])
        status, read = self.request('POST', '/delegate/api/download', {'path': path}, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(read['result']['content_base64']), data)
        status, refused = self.request('POST', '/delegate/api/privileged_op', {
            'action': 'service_restart', 'unit': 'ssh'}, token=token)
        self.assertEqual(status, 400)
        self.assertFalse(refused['ok'])
        rpc = {'jsonrpc': '2.0', 'id': 11, 'method': 'tools/list', 'params': {}}
        status, mcp = self.request('POST', '/delegate/mcp', rpc, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(any(t['name'] == 'exec' for t in mcp['result']['tools']))
        status, ended = self.request('POST', '/delegate/api/finish', {}, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(ended['result']['revoked'])
        self.assertEqual(self.request('GET', '/delegate/api/tools', token=token)[0], 401)
        self.assertEqual(self.request('POST', '/delegate/mcp', rpc, token=token)[0], 401)
        self.assertEqual(self.request('POST', '/delegate/api/exec', {'command': 'id -u'}, token=token)[0], 401)
        audit = d.AUDIT_PATH.read_text()
        self.assertNotIn(password, audit)
        self.assertNotIn(token, audit)

    def test_reject_unknown_routes_and_browser_origin(self):
        gid, password = self.prepare_grant()
        self.assertEqual(self.request('POST', '/delegate/api/unknown', {})[0], 404)
        self.assertEqual(self.request('GET', '/delegate/api/session')[0], 401)
        self.assertEqual(self.request('POST', '/delegate/activate', {'password': password},
                                      origin='https://untrusted.example')[0], 403)
        status, activated = self.request('POST', '/delegate/activate', {'password': password})
        self.assertEqual(status, 200)
        token = activated['access_token']
        self.assertEqual(self.request('POST', '/delegate/api/exec', {'command': 'pwd'}, token=token,
                                      origin='https://untrusted.example')[0], 403)
        self.assertEqual(self.request('POST', '/delegate/api/exec', {'command': ''}, token=token)[0], 400)
        self.assertEqual(self.request('POST', '/delegate/api/exec', {}, token=token)[0], 400)


if __name__ == '__main__':
    unittest.main()

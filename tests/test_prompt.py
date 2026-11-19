import io
import contextlib
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import prompt
import delegatectl


class HandoffTests(unittest.TestCase):
    def test_operator_handoff_exact_data(self):
        data = prompt.render_grant_prompt(
            mode='operator', endpoint='https://gateway.example/delegate/mcp',
            activation_url='https://gateway.example/delegate/activate',
            password='test-only-secret-not-a-real-password', grant_id='example-grant',
            activation_deadline='2026-11-19T16:00:00Z', session_seconds=1800,
            agents_path='/etc/agents/AGENTS.md')
        for expected in ('https://gateway.example/delegate/mcp',
                         'https://gateway.example/delegate/activate',
                         'test-only-secret-not-a-real-password',
                         '/etc/agents/AGENTS.md', '30 minutes', 'finish tool',
                         'FIRST remote action', 'unprivileged'):
            self.assertIn(expected, data)
        self.assertNotIn('ROOT: full VPS administration', data)
        self.assertNotIn('mandrock-ssh.duckdns.org', data)

    def test_root_handoff_is_explicit(self):
        data = prompt.render_grant_prompt(
            mode='root', endpoint='https://gateway.example/delegate/mcp',
            activation_url='https://gateway.example/delegate/activate',
            password='test-only', grant_id='root-grant',
            activation_deadline='2026-11-19T16:00:00Z', session_seconds=900,
            agents_path='/srv/rules/AGENTS.md')
        self.assertIn('ROOT: full VPS administration', data)
        self.assertIn('15 minutes', data)
        self.assertNotIn('Operator: execute shell commands', data)

    def test_grant_output_and_cred_are_same_password(self):
        class Args:
            mode = 'root'
            activate_ttl = 600
            session_ttl = 120

        sent = {}
        def capture(key, value):
            sent[key] = value
        out = io.StringIO()
        with (mock.patch.object(delegatectl, 'create_grant', return_value=('abcd1234', 'generated-test-password', 1795104600)),
              mock.patch.object(delegatectl, 'set_cred', side_effect=capture),
              mock.patch.object(delegatectl, 'CRED_BIN', '/usr/local/bin/cred'),
              contextlib.redirect_stdout(out)):
            delegatectl.grant(Args())
        self.assertEqual(sent['PASSWORD'], 'generated-test-password')
        self.assertIn('generated-test-password', out.getvalue())
        self.assertIn('https://', out.getvalue() if delegatectl.PUBLIC_URL.startswith('https://') else 'https://example.test')
        self.assertIn('COPY / PASTE TO EXTERNAL AGENT', out.getvalue())


if __name__ == '__main__':
    unittest.main()

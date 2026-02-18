import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest
from unittest.mock import patch, MagicMock, call
import socket
import threading
import types
import os
import sys
import json
import tempfile
import shutil

# Import main modules
import honeypot
from modules import vfs, commands, export

class TestHoneypotCore(unittest.TestCase):
    def setUp(self):
        self.state = honeypot.HoneypotState()
        self.config = honeypot.CONFIG.copy()

    def test_log_event_and_capture_credential(self):
        honeypot.log_event('INFO', 'SSH', '1.2.3.4', 'Test event')
        self.assertTrue(len(honeypot.state.events) > 0)
        honeypot.capture_credential('1.2.3.4', 1234, 'SSH', 'user', 'pass')
        self.assertTrue(len(honeypot.state.credentials) > 0)

    def test_discord_alerts(self):
        with patch('requests.post') as mock_post:
            honeypot.discord_login_alert('SSH', '1.2.3.4', 'user', 'pass')
            honeypot.discord_sudo_alert('1.2.3.4', 'user', 'pass', 'sudo ls')
            honeypot.discord_connection_alert('SSH', '1.2.3.4', 1234)
            self.assertTrue(mock_post.called)

    def test_export_to_json_and_xml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, 'report.json')
            xml_file = os.path.join(tmpdir, 'report.xml')
            xslt_file = os.path.join(tmpdir, 'report.xslt')
            honeypot.state.credentials.append(honeypot.CapturedCredential('now', 'ip', 1, 'svc', 'u', 'p', 'login'))
            honeypot.state.events.append(honeypot.LogEvent('now', 'INFO', 'svc', 'ip', 'msg'))
            honeypot.state.sessions['sid'] = honeypot.ActiveSession('sid', 'ip', 1, 'svc', 'now', 'u')
            export.export_to_json(json_file, self.config, honeypot.state)
            export.export_to_xml(xml_file, self.config, honeypot.state)
            self.assertTrue(os.path.exists(json_file))
            self.assertTrue(os.path.exists(xml_file))
            self.assertTrue(os.path.exists(xslt_file))

class TestVFS(unittest.TestCase):
    def test_get_virtual_fs_entry(self):
        self.assertIsNotNone(vfs.get_virtual_fs_entry('/etc', 'root'))
        self.assertIsNone(vfs.get_virtual_fs_entry('/etc/passwd', 'root'))
        self.assertIsNotNone(vfs.get_virtual_fs_entry('/home/someuser', 'root'))
        self.assertIsNone(vfs.get_virtual_fs_entry('/notfound', 'root'))

    def test_fake_file_contents(self):
        for path, content in vfs.FAKE_FILE_CONTENTS.items():
            self.assertIsInstance(content, str)

class TestFakeShell(unittest.TestCase):
    def setUp(self):
        self.conn = MagicMock()
        self.addr = ('1.2.3.4', 1234)
        self.state = honeypot.HoneypotState()
        self.config = honeypot.CONFIG.copy()
        self.log_event = MagicMock()
        self.capture_credential = MagicMock()
        self.discord_login_alert = MagicMock()
        self.discord_sudo_alert = MagicMock()
        self.ActiveSession = honeypot.ActiveSession

    def test_shell_login_and_run(self):
        shell = commands.FakeShell(self.conn, self.addr, 'SSH', self.config, self.state, self.log_event,
                                   self.capture_credential, self.discord_login_alert, self.discord_sudo_alert, self.ActiveSession)
        with patch.object(shell, 'do_login', return_value=True), \
             patch.object(shell, 'run_shell', return_value=None):
            shell.do_login()
            shell.run_shell()
        self.assertTrue(shell)

    def test_execute_shell_command(self):
        result = commands.execute_shell_command('ls', '/home', False, 'user', self.addr, self.config, self.log_event, {})
        self.assertIsInstance(result, str)

    def test_resolve_path(self):
        path = commands.resolve_path('..', '/home/user', False, 'user')
        self.assertTrue(isinstance(path, str))

class TestExportModule(unittest.TestCase):
    def setUp(self):
        self.state = honeypot.HoneypotState()
        self.config = honeypot.CONFIG.copy()
        self.state.credentials.append(honeypot.CapturedCredential('now', 'ip', 1, 'svc', 'u', 'p', 'login'))
        self.state.events.append(honeypot.LogEvent('now', 'INFO', 'svc', 'ip', 'msg'))
        self.state.sessions['sid'] = honeypot.ActiveSession('sid', 'ip', 1, 'svc', 'now', 'u')

    def test_export_to_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, 'report.json')
            export.export_to_json(json_file, self.config, self.state)
            self.assertTrue(os.path.exists(json_file))
            with open(json_file) as f:
                data = json.load(f)
                self.assertIn('meta', data)
                self.assertIn('summary', data)

    def test_export_to_xml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            xml_file = os.path.join(tmpdir, 'report.xml')
            xslt_file = os.path.join(tmpdir, 'report.xslt')
            export.export_to_xml(xml_file, self.config, self.state)
            self.assertTrue(os.path.exists(xml_file))
            self.assertTrue(os.path.exists(xslt_file))

class TestServiceHandlers(unittest.TestCase):
    def setUp(self):
        self.state = honeypot.HoneypotState()
        self.config = honeypot.CONFIG.copy()
        self.addr = ("127.0.0.1", 12345)
        self.session_id = "testsession"

    def test_ssh_handler_fallback(self):
        with patch("honeypot.HAS_PARAMIKO", False):
            mock_conn = MagicMock()
            mock_conn.recv.return_value = b"SSH-2.0-client\r\n"
            try:
                honeypot.ssh_handler(mock_conn, self.addr)
            except Exception as e:
                self.fail(f"ssh_handler fallback raised: {e}")

    def test_telnet_handler(self):
        mock_conn = MagicMock()
        mock_conn.recv.return_value = b"ls\n"
        try:
            honeypot.telnet_handler(mock_conn, self.addr)
        except Exception as e:
            self.fail(f"telnet_handler raised: {e}")

    def test_ftp_handler(self):
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [b"USER test\r\n", b"PASS test\r\n", b"QUIT\r\n"]
        mock_conn.getsockname.return_value = ("127.0.0.1", 2121)
        try:
            honeypot.ftp_handler(mock_conn, self.addr)
        except Exception as e:
            self.fail(f"ftp_handler raised: {e}")

    def test_smb_handler(self):
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [b'\x00\x00\x00\x40', b'\xffSMB' + b'\x72' + b'\x00'*59]
        try:
            honeypot.smb_handler(mock_conn, self.addr)
        except Exception as e:
            self.fail(f"smb_handler raised: {e}")

if __name__ == '__main__':
    unittest.main()

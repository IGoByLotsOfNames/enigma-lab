# Path: tests/test_demo_entry.py
"""CLI lifecycle contracts; the root also verifies the real launcher and Ctrl+C."""

import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

from enigma_demo import __main__ as entry


class DemoEntryTests(unittest.TestCase):
    def test_help_exits_cleanly_without_binding_a_port(self):
        stdout, stderr = StringIO(), StringIO()
        with patch.object(entry, "create_server") as create:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    entry.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        create.assert_not_called()
        self.assertIn("--open-browser", stdout.getvalue())
        self.assertIn("--port", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_invalid_ports_report_usage_errors_without_tracebacks(self):
        for port in ("-1", "65536", "not-an-integer"):
            stdout, stderr = StringIO(), StringIO()
            with self.subTest(port=port), redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    entry.main(["--port", port])
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("error:", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_bind_failure_is_a_clean_usage_error(self):
        stdout, stderr = StringIO(), StringIO()
        with patch.object(entry, "create_server", side_effect=OSError("address in use")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    entry.main(["--port", "60000"])
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("address in use", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_keyboard_interrupt_closes_server_without_opening_browser(self):
        server = Mock(url="http://127.0.0.1:60000/")
        server.serve_forever.side_effect = KeyboardInterrupt
        server.close.return_value = True
        stdout, stderr = StringIO(), StringIO()
        with patch.object(entry, "create_server", return_value=server) as create:
            with patch.object(entry.webbrowser, "open") as browser:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    status = entry.main([])
        self.assertEqual(status, 0)
        create.assert_called_once_with(0)
        server.serve_forever.assert_called_once_with()
        server.close.assert_called_once_with()
        browser.assert_not_called()
        self.assertEqual(stdout.getvalue(), server.url + "\n")
        self.assertEqual(stderr.getvalue(), "")

    def test_opt_in_browser_open_uses_the_bound_local_url(self):
        server = Mock(url="http://127.0.0.1:60001/")
        server.serve_forever.side_effect = KeyboardInterrupt
        server.close.return_value = True
        with patch.object(entry, "create_server", return_value=server):
            with patch.object(entry.webbrowser, "open") as browser:
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    status = entry.main(["--port", "60001", "--open-browser"])
        self.assertEqual(status, 0)
        browser.assert_called_once_with(server.url, new=2)
        server.close.assert_called_once_with()

    def test_pending_worker_shutdown_is_reported_as_unsuccessful(self):
        server = Mock(url="http://127.0.0.1:60002/")
        server.serve_forever.side_effect = KeyboardInterrupt
        server.close.return_value = False
        stderr = StringIO()
        with patch.object(entry, "create_server", return_value=server):
            with redirect_stdout(StringIO()), redirect_stderr(stderr):
                status = entry.main([])
        self.assertEqual(status, 1)
        self.assertIn("cancellation is pending", stderr.getvalue())
        server.close.assert_called_once_with()

    def test_unexpected_serving_error_still_closes_server(self):
        server = Mock(url="http://127.0.0.1:60003/")
        server.serve_forever.side_effect = RuntimeError("controlled serving fault")
        server.close.return_value = True
        with patch.object(entry, "create_server", return_value=server):
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                with self.assertRaisesRegex(RuntimeError, "controlled serving fault"):
                    entry.main([])
        server.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

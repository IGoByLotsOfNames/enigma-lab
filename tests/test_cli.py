# Path: tests/test_cli.py
"""User-visible command behaviour, with real engine/search and fresh processes."""

import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from enigma_lab import cli


class CliTests(unittest.TestCase):
    def invoke(self, arguments):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = cli.main(arguments)
        return result, stdout.getvalue(), stderr.getvalue()

    def assert_usage_error(self, arguments):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                cli.main(arguments)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_default_transform_and_ascii_whitespace(self):
        status, stdout, stderr = self.invoke(["transform", "--text", "a a\taa\nA"])
        self.assertEqual(status, 0)
        self.assertEqual(stdout, "BDZGO\n")
        self.assertEqual(stderr, "")

    def test_nondefault_key_published_ciphertext(self):
        status, stdout, stderr = self.invoke(
            [
                "transform",
                "--rotors",
                "II",
                "IV",
                "V",
                "--reflector",
                "B",
                "--rings",
                "BUL",
                "--positions",
                "WXC",
                "--plugboard",
                "AV BS CG DL FU HZ IN KM OW RX",
                "--text",
                "BLA",
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(stdout, "KCH\n")
        self.assertEqual(stderr, "")

    def test_trace_json_contains_signal_and_state_history(self):
        status, stdout, stderr = self.invoke(["transform", "--text", "aaaaa", "--trace"])
        payload = json.loads(stdout)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(payload["input"], "AAAAA")
        self.assertEqual(payload["output"], "BDZGO")
        self.assertEqual(payload["final_positions"], "AAF")
        self.assertEqual(payload["settings"]["rotors"], ["I", "II", "III"])
        self.assertEqual(len(payload["trace"]), 5)
        self.assertEqual(payload["trace"][0]["before"], "AAA")
        self.assertEqual(payload["trace"][0]["after"], "AAB")
        self.assertEqual(payload["trace"][0]["steps"], [False, False, True])
        self.assertEqual(len(payload["trace"][0]["path"]), 9)
        self.assertEqual("".join(trace["output_letter"] for trace in payload["trace"]), "BDZGO")

    def test_empty_transform_has_explicit_successful_output(self):
        status, stdout, stderr = self.invoke(["transform", "--text", " \t"])
        self.assertEqual((status, stdout, stderr), (0, "\n", ""))
        status, stdout, stderr = self.invoke(["transform", "--text", "", "--trace"])
        payload = json.loads(stdout)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(payload["output"], "")
        self.assertEqual(payload["trace"], [])
        self.assertEqual(payload["final_positions"], "AAA")

    def test_real_search_no_match_is_success_not_usage_error(self):
        # Only a single-letter CLI search is needed here. The sole full
        # five-letter oracle search is in test_search.py.
        status, stdout, stderr = self.invoke(
            [
                "search",
                "--ciphertext",
                " a ",
                "--crib",
                "\tA\n",
                "--offset",
                "0",
            ]
        )
        payload = json.loads(stdout)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(payload["matches"], [])
        self.assertEqual(payload["ciphertext"], "A")
        self.assertEqual(payload["crib"], "A")
        self.assertEqual(payload["candidates_checked"], 17576)
        self.assertEqual(payload["characters_transformed"], 17576)
        self.assertTrue(payload["complete"])
        self.assertTrue(payload["global_domain"])
        self.assertIsNone(payload["searched_positions"])

    def test_invalid_syntax_exits_two(self):
        for arguments in (
            [],
            ["unknown"],
            ["transform"],
            ["search"],
            ["search", "--ciphertext", "B", "--crib", "A", "--offset", "word"],
        ):
            with self.subTest(arguments=arguments):
                self.assert_usage_error(arguments)

    def test_validation_errors_exit_two_without_partial_output(self):
        cases = [
            ["transform", "--text", "AAAAA!"],
            ["transform", "--text", "Aſ"],
            ["transform", "--text", "A\u00a0B"],
            ["transform", "--text", "AAA", "--rotors", "I", "I", "III"],
            ["transform", "--text", "AAA", "--reflector", "thin-B"],
            ["transform", "--text", "AAA", "--rings", "AA1"],
            ["transform", "--text", "AAA", "--plugboard", "AB AC"],
            ["search", "--ciphertext", "", "--crib", "A"],
            ["search", "--ciphertext", "B", "--crib", " "],
            ["search", "--ciphertext", "B", "--crib", "A", "--offset", "-1"],
            ["search", "--ciphertext", "B", "--crib", "AA"],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                self.assert_usage_error(arguments)

    def test_help_exits_zero_and_describes_scope(self):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("transform", stdout.getvalue())
        self.assertIn("search", stdout.getvalue())
        self.assertIn("I-V", stdout.getvalue())

    def test_interrupted_search_returns_130_without_complete_json(self):
        # Narrow fault injection only for Ctrl+C, otherwise the real parser,
        # key validation, normalization and reporting are exercised.
        with patch.object(cli, "search_positions", side_effect=KeyboardInterrupt) as search:
            status, stdout, stderr = self.invoke(["search", "--ciphertext", "B", "--crib", "A"])
        search.assert_called_once()
        self.assertEqual(status, 130)
        self.assertEqual(stdout, "")
        self.assertIn("Interrupted", stderr)
        self.assertNotIn("Traceback", stderr)


class SubprocessCliTests(unittest.TestCase):
    def run_child(self, arguments):
        root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(root)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, "-X", "utf8", "-B", *arguments],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            check=False,
        )

    def test_import_is_quiet_with_no_stdin(self):
        process = self.run_child(
            [
                "-c",
                "import enigma_lab; import enigma_lab.engine; "
                "import enigma_lab.search; import enigma_lab.cli; import enigma_lab.__main__",
            ]
        )
        self.assertEqual((process.returncode, process.stdout, process.stderr), (0, "", ""))

    def test_real_module_entry_point(self):
        process = self.run_child(["-m", "enigma_lab", "transform", "--text", "AAAAA"])
        self.assertEqual((process.returncode, process.stdout, process.stderr), (0, "BDZGO\n", ""))

    def test_real_module_invalid_unicode_is_clean_usage_error(self):
        process = self.run_child(["-m", "enigma_lab", "transform", "--text", "Aſ"])
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertIn("error:", process.stderr)
        self.assertNotIn("Traceback", process.stderr)


if __name__ == "__main__":
    unittest.main()

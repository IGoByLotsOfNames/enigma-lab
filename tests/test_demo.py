# Path: tests/test_demo.py
"""Local demo contracts through service calls and a real loopback HTTP server."""

import json
import threading
import time
import unittest
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from enigma_demo import service
from enigma_demo.jobs import JobManager
from enigma_demo.server import create_server
from enigma_lab.search import search_positions
from enigma_lab.search_early import search_positions_early


def settings(**overrides):
    value = {
        "rotors": ["I", "II", "III"],
        "reflector": "B",
        "rings": "AAA",
        "positions": "AAA",
        "plugboard": "",
    }
    value.update(overrides)
    return value


def transform_request(text="AAAAA", **key_overrides):
    return {"settings": settings(**key_overrides), "text": text}


def search_request(**overrides):
    value = {
        "settings": settings(),
        "ciphertext": "BDZGO",
        "crib": "AAAAA",
        "offset": 0,
        "strategy": "early",
    }
    value.update(overrides)
    return value


@contextmanager
def running_server(**kwargs):
    server = create_server(port=0, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.close()
        thread.join(timeout=5)


class TransformServiceTests(unittest.TestCase):
    def test_published_default_vector_and_trace(self):
        result = service.transform_payload(transform_request("aa aa a"))
        self.assertEqual(result["input"], "AAAAA")
        self.assertEqual(result["output"], "BDZGO")
        self.assertEqual(result["final_positions"], "AAF")
        self.assertEqual(len(result["trace"]), 5)
        first = result["trace"][0]
        self.assertEqual(first["before"], "AAA")
        self.assertEqual(first["after"], "AAB")
        self.assertEqual(tuple(first["steps"]), (False, False, True))
        self.assertEqual(first["output_letter"], "B")
        self.assertEqual(len(first["path"]), 9)

    def test_each_request_starts_from_its_declared_initial_state(self):
        first = service.transform_payload(transform_request())
        service.transform_payload(transform_request("HELLOWORLD", positions="XYZ"))
        second = service.transform_payload(transform_request())
        self.assertEqual(first, second)

    def test_empty_transform_is_explicit_and_does_not_step(self):
        result = service.transform_payload(transform_request(" \t\n", positions="XYZ"))
        self.assertEqual(result["input"], "")
        self.assertEqual(result["output"], "")
        self.assertEqual(result["trace"], [])
        self.assertEqual(result["final_positions"], "XYZ")

    def test_published_nondefault_key(self):
        result = service.transform_payload(
            transform_request(
                "BLA",
                rotors=["II", "IV", "V"],
                rings="BUL",
                positions="WXC",
                plugboard="AV BS CG DL FU HZ IN KM OW RX",
            )
        )
        self.assertEqual(result["output"], "KCH")

    def test_invalid_ascii_and_key_settings_are_rejected(self):
        requests = [
            transform_request("AB!"),
            transform_request("ABſ"),
            transform_request("ABß"),
            transform_request("A\u00a0B"),
            transform_request(plugboard="AB AC"),
            transform_request(rotors=["I", "I", "III"]),
            transform_request(rings="AA1"),
        ]
        for request in requests:
            with self.subTest(request=request), self.assertRaises(ValueError):
                service.transform_payload(request)

    def test_text_limit_applies_to_normalized_letters(self):
        result = service.transform_payload(transform_request("a " * 256))
        self.assertEqual(len(result["input"]), 256)
        self.assertEqual(len(result["trace"]), 256)
        with self.assertRaises(ValueError):
            service.transform_payload(transform_request("A" * 257))

    def test_malformed_payloads_are_controlled_errors(self):
        for request in (
            None,
            [],
            "AAAAA",
            {"text": 1, "settings": settings()},
            {"text": "A", "settings": []},
            {"text": "A", "extra": True},
            {"text": "A", "settings": {"extra": True}},
        ):
            with self.subTest(request=request), self.assertRaises(ValueError):
                service.transform_payload(request)

    def test_saved_transform_samples_match_their_external_reference_values(self):
        source = Path(__file__).resolve().parents[1] / "enigma_demo" / "samples.json"
        samples = json.loads(source.read_text(encoding="utf-8"))
        transforms = [sample for sample in samples if sample["mode"] == "transform"]
        self.assertEqual(len(transforms), 3)
        for sample in transforms:
            with self.subTest(sample=sample["id"]):
                result = service.transform_payload(
                    {"text": sample["text"], "settings": sample["settings"]}
                )
                self.assertEqual(result["output"], sample["expected"]["output"])
                self.assertEqual(result["final_positions"], sample["expected"]["final_positions"])
                self.assertEqual(
                    [trace["after"] for trace in result["trace"]],
                    sample["expected"]["windows_after_keys"],
                )


class SearchServiceTests(unittest.TestCase):
    def test_normalization_and_default_strategy(self):
        request = service.prepare_search({"ciphertext": "b d\nzgo", "crib": "a a"})
        self.assertEqual(request.ciphertext, "BDZGO")
        self.assertEqual(request.crib, "AA")
        self.assertEqual(request.offset, 0)
        self.assertEqual(request.strategy, "baseline")

    def test_invalid_search_contracts(self):
        requests = [search_request(offset=value) for value in (-1, True, 0.0, "0", None, 1)]
        requests += [search_request(strategy=value) for value in (None, "auto", [], True)]
        requests += [search_request(ciphertext=value) for value in ("", "A" * 257, "BDZGO!", None)]
        requests += [search_request(crib=value) for value in ("", "AAAAAA", "ſ", None)]
        requests += [search_request(extra=True), None, []]
        for request in requests:
            with self.subTest(request=request), self.assertRaises(ValueError):
                service.prepare_search(request)

    def test_all_search_samples_have_valid_requests_and_retained_evidence(self):
        source = Path(__file__).resolve().parents[1] / "enigma_demo" / "samples.json"
        samples = json.loads(source.read_text(encoding="utf-8"))
        searches = [sample for sample in samples if sample["mode"] == "search"]
        self.assertEqual(len(searches), 5)
        for sample in searches:
            with self.subTest(sample=sample["id"]):
                payload = {
                    key: sample[key]
                    for key in ("settings", "ciphertext", "crib", "offset", "strategy")
                }
                request = service.prepare_search(payload)
                self.assertEqual(request.ciphertext, sample["ciphertext"])
                self.assertEqual(request.offset, sample["offset"])
                self.assertEqual(sample["expected"]["candidates_checked"], 17576)
                self.assertTrue(sample["expected"]["complete"])
        basic = next(sample for sample in searches if sample["id"] == "basic-B-5")
        oracle = json.loads(
            (Path(__file__).parent / "fixtures" / "oracle_fixtures.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            basic["expected"]["matches"], oracle["search_fixtures"][0]["matching_initial_windows"]
        )


class HttpDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = running_server()
        cls.server = cls.context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def request(self, method, path, payload=None, headers=None, raw=None):
        supplied = {} if headers is None else dict(headers)
        body = raw
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        if method == "POST":
            defaults = {
                "Origin": self.server.origin,
                "X-Enigma-Token": self.server.token,
                "Content-Type": "application/json",
            }
            defaults.update(supplied)
            supplied = {key: value for key, value in defaults.items() if value is not None}
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=supplied)
            response = connection.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            connection.close()

    def test_bootstrap_exposes_only_local_api_contract(self):
        status, headers, data = self.request("GET", "/api/bootstrap")
        result = json.loads(data)
        self.assertEqual(status, 200)
        self.assertEqual(result["token"], self.server.token)
        self.assertEqual(result["strategies"], ["baseline", "early"])
        self.assertEqual(result["limits"]["max_text_letters"], 256)
        self.assertEqual(result["limits"]["max_body_bytes"], 32768)
        self.assertIsInstance(result["samples"], list)
        self.assertTrue(result["samples"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_a_second_live_server_cannot_bind_the_same_local_port(self):
        second = None
        try:
            with self.assertRaises(OSError):
                second = create_server(port=self.server.server_port)
        finally:
            if second is not None:
                second.close()
        # A failed second bind must leave the original server usable.
        status, _, data = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["token"], self.server.token)

    def test_http_transform_uses_real_engine(self):
        status, _, data = self.request("POST", "/api/transform", transform_request())
        result = json.loads(data)
        self.assertEqual(status, 200)
        self.assertEqual(result["output"], "BDZGO")
        self.assertEqual(result["trace"][0]["after"], "AAB")

    def test_host_rebinding_and_foreign_origin_are_rejected(self):
        for method, path, headers in (
            ("GET", "/api/bootstrap", {"Host": "attacker.example"}),
            ("GET", "/api/bootstrap", {"Origin": "https://attacker.example"}),
            ("POST", "/api/transform", {"Host": "attacker.example"}),
            ("POST", "/api/transform", {"Origin": "https://attacker.example"}),
            ("POST", "/api/transform", {"Origin": "null"}),
        ):
            with self.subTest(method=method, headers=headers):
                status, _, _ = self.request(
                    method, path, transform_request() if method == "POST" else None, headers=headers
                )
                self.assertEqual(status, 403)

    def test_post_requires_exact_origin_and_per_launch_token(self):
        for headers in (
            {"Origin": None},
            {"X-Enigma-Token": None},
            {"X-Enigma-Token": "wrong-token"},
            {"X-Enigma-Token": "é"},
        ):
            with self.subTest(headers=headers):
                status, _, _ = self.request("POST", "/api/transform", transform_request(), headers)
                self.assertEqual(status, 403)

    def test_invalid_json_and_payloads_are_bad_requests(self):
        for raw in (b"{", b"[]", b"null", b'"text"', b"\xff"):
            with self.subTest(raw=raw):
                status, _, data = self.request("POST", "/api/transform", raw=raw)
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(data))
        status, _, data = self.request("POST", "/api/transform", transform_request("AB!"))
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(data))

    def test_content_type_and_body_limit(self):
        status, _, _ = self.request(
            "POST", "/api/transform", transform_request(), {"Content-Type": "text/plain"}
        )
        self.assertEqual(status, 415)
        status, _, _ = self.request("POST", "/api/transform", raw=b" " * 32769)
        self.assertEqual(status, 413)

    def test_transfer_encoding_and_nonfinite_json_are_rejected(self):
        status, _, _ = self.request(
            "POST", "/api/transform", transform_request(), {"Transfer-Encoding": "chunked"}
        )
        self.assertEqual(status, 400)
        for raw in (b'{"text": NaN}', b'{"text": Infinity}'):
            with self.subTest(raw=raw):
                status, _, _ = self.request("POST", "/api/transform", raw=raw)
                self.assertEqual(status, 400)
        for length in ("invalid", "-1"):
            with self.subTest(length=length):
                status, _, _ = self.request(
                    "POST", "/api/transform", raw=b"{}", headers={"Content-Length": length}
                )
                self.assertEqual(status, 400)

    def test_internal_payload_failure_is_sanitized(self):
        with patch(
            "enigma_demo.server.transform_payload",
            side_effect=RuntimeError("private details must not leak"),
        ):
            status, _, data = self.request("POST", "/api/transform", transform_request())
        self.assertEqual(status, 500)
        self.assertNotIn(b"private details", data)
        self.assertNotIn(b"Traceback", data)
        self.assertIn("error", json.loads(data))

    def test_live_search_submit_poll_and_completed_cancel(self):
        status, _, data = self.request(
            "POST", "/api/search", search_request(ciphertext="A", crib="A")
        )
        self.assertEqual(status, 202)
        job = json.loads(data)
        deadline = time.monotonic() + 5
        while job["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.005)
            status, _, data = self.request("GET", f"/api/search/{job['id']}")
            self.assertEqual(status, 200)
            job = json.loads(data)
        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["matches"], [])
        self.assertEqual(job["candidates_checked"], 17576)
        status, _, data = self.request("POST", f"/api/search/{job['id']}/cancel", {})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "complete")
        status, _, _ = self.request("POST", f"/api/search/{job['id']}/cancel", {"unexpected": True})
        self.assertEqual(status, 400)

    def test_live_busy_cancel_and_shutdown_contracts(self):
        entered, release = threading.Event(), threading.Event()

        def controlled(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test did not release running search")
            return search_positions_early(*args, **kwargs)

        manager = JobManager(search_functions={"baseline": search_positions, "early": controlled})
        with running_server(job_manager=manager) as server:
            self.server = server
            try:
                status, _, data = self.request("POST", "/api/search", search_request())
                self.assertEqual(status, 202)
                job = json.loads(data)
                self.assertTrue(entered.wait(5))
                status, _, _ = self.request("POST", "/api/search", search_request())
                self.assertEqual(status, 409)
                status, _, data = self.request("POST", f"/api/search/{job['id']}/cancel", {})
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(data)["cancel_requested"])
                release.set()
                self.assertTrue(manager.close())
                status, _, data = self.request("GET", f"/api/search/{job['id']}")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(data)["status"], "cancelled")
                status, _, _ = self.request("POST", "/api/search", search_request())
                self.assertEqual(status, 503)
            finally:
                release.set()
                del self.server

    def test_unsupported_methods_and_response_headers(self):
        status, headers, _ = self.request("PUT", "/api/bootstrap")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_static_allowlist_does_not_serve_project_files(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertTrue(body)
        for path, content_type in (("/app.css", "text/css"), ("/app.js", "text/javascript")):
            with self.subTest(asset=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertIn(content_type, headers.get("Content-Type", ""))
                self.assertTrue(body)
        for path in (
            "/README.txt",
            "/enigma_lab/engine.py",
            "/../README.txt",
            "/%2e%2e/README.txt",
            "/tests/fixtures/oracle_fixtures.json",
        ):
            with self.subTest(path=path):
                status, _, _ = self.request("GET", path)
                self.assertEqual(status, 404)

    def test_unknown_api_paths_and_job_ids(self):
        for method, path in (
            ("GET", "/api/unknown"),
            ("GET", "/api/search/missing"),
            ("POST", "/api/search/missing/cancel"),
            ("POST", "/api/unknown"),
            ("GET", "/api/search/" + "0" * 32),
            ("POST", "/api/search/" + "0" * 32 + "/cancel"),
        ):
            with self.subTest(method=method, path=path):
                status, _, _ = self.request(method, path, {} if method == "POST" else None)
                self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()

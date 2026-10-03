# Path: tests/test_demo_jobs.py
"""Search-job lifecycle checks with real cipher work and controlled fault boundaries."""

import json
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from enigma_demo.jobs import BusyError, ClosedError, JobManager
from enigma_demo.service import prepare_search
from enigma_lab.search import search_positions
from enigma_lab.search_early import search_positions_early
from tests.test_demo import search_request


def wait_terminal(manager, job_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = manager.get(job_id)
        if snapshot["status"] != "running":
            return snapshot
        time.sleep(0.005)
    raise AssertionError("search did not reach a terminal state within test safety timeout")


class JobManagerTests(unittest.TestCase):
    def test_configuration_rejects_unbounded_or_invalid_values(self):
        cases = [{"chunk_size": value} for value in (True, 0, 17577, 1.5)]
        cases += [{"max_jobs": value} for value in (True, 0, 9)]
        cases += [{"timeout_seconds": value} for value in (True, 0, -1, float("nan"), float("inf"))]
        cases += [
            {"search_functions": {}},
            {"clock": None},
            {"search_functions": {"baseline": None, "early": search_positions_early}},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                JobManager(**kwargs)

    def test_real_chunked_search_matches_independent_complete_oracle(self):
        oracle = json.loads(
            (Path(__file__).parent / "fixtures" / "oracle_fixtures.json").read_text(
                encoding="utf-8"
            )
        )
        fixture = oracle["search_fixtures"][0]
        with self.subTest(strategy="early"):
            manager = JobManager(chunk_size=64)
            try:
                started = manager.submit(prepare_search(search_request(strategy="early")))
                complete = wait_terminal(manager, started["id"])
                self.assertEqual(complete["status"], "complete")
                self.assertEqual(complete["matches"], fixture["matching_initial_windows"])
                self.assertEqual(complete["candidates_checked"], fixture["candidates_checked"])
                self.assertEqual(complete["domain_size"], 17576)
                self.assertFalse(complete["partial_matches_unverified"])
                self.assertTrue(complete["result"]["complete"])
                self.assertTrue(complete["result"]["global_domain"])
                self.assertEqual(tuple(complete["result"]["matches"]), ("AAA",))
                self.assertLess(
                    complete["characters_transformed"], fixture["characters_transformed"]
                )
            finally:
                self.assertTrue(manager.close())

    def test_baseline_strategy_returns_full_counter_and_no_match_success(self):
        manager = JobManager(chunk_size=511)
        try:
            request = prepare_search(search_request(ciphertext="A", crib="A", strategy="baseline"))
            started = manager.submit(request)
            complete = wait_terminal(manager, started["id"])
            self.assertEqual(complete["status"], "complete")
            self.assertEqual(complete["strategy"], "baseline")
            self.assertEqual(complete["matches"], [])
            self.assertEqual(complete["characters_transformed"], 17576)
            self.assertEqual(complete["candidates_checked"], 17576)
            self.assertFalse(complete["partial_matches_unverified"])
        finally:
            self.assertTrue(manager.close())

    def test_busy_guard_and_cancellation_retain_explicit_partial_state(self):
        entered_second, release = threading.Event(), threading.Event()
        calls = 0

        def controlled(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                entered_second.set()
                if not release.wait(5):
                    raise AssertionError("test failed to release controlled search")
            return search_positions_early(*args, **kwargs)

        manager = JobManager(
            chunk_size=64, search_functions={"baseline": search_positions, "early": controlled}
        )
        try:
            started = manager.submit(prepare_search(search_request()))
            self.assertTrue(entered_second.wait(5))
            partial = manager.get(started["id"])
            self.assertEqual(partial["candidates_checked"], 64)
            self.assertIn("AAA", partial["matches"])
            self.assertTrue(partial["partial_matches_unverified"])
            self.assertIsNone(partial["result"])
            with self.assertRaises(BusyError):
                manager.submit(prepare_search(search_request()))
            cancel = manager.cancel(started["id"])
            self.assertTrue(cancel["cancel_requested"])
            release.set()
            stopped = wait_terminal(manager, started["id"])
            self.assertEqual(stopped["status"], "cancelled")
            self.assertLess(stopped["candidates_checked"], 17576)
            self.assertTrue(stopped["partial_matches_unverified"])
            self.assertIsNone(stopped["result"])
        finally:
            release.set()
            self.assertTrue(manager.close())

    def test_timeout_is_cooperative_and_cannot_claim_completion(self):
        class Clock:
            now = 0.0

            def __call__(self):
                return self.now

        clock = Clock()

        def advance_clock(*args, **kwargs):
            result = search_positions_early(*args, **kwargs)
            clock.now += 2.0
            return result

        manager = JobManager(
            chunk_size=64,
            timeout_seconds=1,
            clock=clock,
            search_functions={"baseline": search_positions, "early": advance_clock},
        )
        try:
            started = manager.submit(prepare_search(search_request()))
            stopped = wait_terminal(manager, started["id"])
            self.assertEqual(stopped["status"], "timed_out")
            self.assertLess(stopped["candidates_checked"], 17576)
            self.assertTrue(stopped["partial_matches_unverified"])
            self.assertIsNone(stopped["result"])
        finally:
            self.assertTrue(manager.close())

    def test_exception_is_failure_without_complete_result(self):
        def fail(*args, **kwargs):
            raise RuntimeError("controlled failure")

        manager = JobManager(search_functions={"baseline": search_positions, "early": fail})
        try:
            started = manager.submit(prepare_search(search_request()))
            failed = wait_terminal(manager, started["id"])
            self.assertEqual(failed["status"], "failed")
            self.assertIsNone(failed["result"])
            self.assertTrue(failed["error"])
        finally:
            self.assertTrue(manager.close())

    def test_incomplete_chunk_is_never_published_as_complete(self):
        def incomplete(*args, **kwargs):
            return replace(search_positions_early(*args, **kwargs), complete=False)

        manager = JobManager(search_functions={"baseline": search_positions, "early": incomplete})
        try:
            started = manager.submit(prepare_search(search_request()))
            failed = wait_terminal(manager, started["id"])
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["candidates_checked"], 0)
            self.assertIsNone(failed["result"])
        finally:
            self.assertTrue(manager.close())

    def test_deadline_after_last_chunk_still_prevents_false_completion(self):
        now = [0.0]

        def complete_after_deadline(*args, **kwargs):
            result = search_positions_early(*args, **kwargs)
            now[0] = 2.0
            return result

        manager = JobManager(
            chunk_size=17576,
            timeout_seconds=1,
            clock=lambda: now[0],
            search_functions={"baseline": search_positions, "early": complete_after_deadline},
        )
        try:
            started = manager.submit(prepare_search(search_request(ciphertext="A", crib="A")))
            stopped = wait_terminal(manager, started["id"])
            self.assertEqual(stopped["candidates_checked"], 17576)
            self.assertEqual(stopped["status"], "timed_out")
            self.assertIsNone(stopped["result"])
            self.assertTrue(stopped["partial_matches_unverified"])
        finally:
            self.assertTrue(manager.close())

    def test_history_is_bounded_and_unknown_ids_are_explicit(self):
        manager = JobManager(max_jobs=2, chunk_size=17576)
        try:
            ids = []
            for _ in range(3):
                started = manager.submit(prepare_search(search_request(ciphertext="A", crib="A")))
                self.assertEqual(wait_terminal(manager, started["id"])["status"], "complete")
                ids.append(started["id"])
            self.assertIsNone(manager.get(ids[0]))
            self.assertIsNotNone(manager.get(ids[1]))
            self.assertIsNotNone(manager.get(ids[2]))
            self.assertIsNone(manager.get("missing"))
            self.assertIsNone(manager.cancel("missing"))
            self.assertEqual(manager.cancel(ids[-1])["status"], "complete")
        finally:
            self.assertTrue(manager.close())

    def test_snapshots_do_not_expose_mutable_internal_state(self):
        manager = JobManager(chunk_size=17576)
        try:
            started = manager.submit(prepare_search(search_request(ciphertext="A", crib="A")))
            final = wait_terminal(manager, started["id"])
            final["matches"].append("AAA")
            final["result"]["matches"] = ("AAA",)
            fresh = manager.get(started["id"])
            self.assertEqual(fresh["matches"], [])
            self.assertEqual(tuple(fresh["result"]["matches"]), ())
        finally:
            self.assertTrue(manager.close())

    def test_close_cancels_work_and_rejects_new_jobs(self):
        entered, release = threading.Event(), threading.Event()

        def controlled(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test failed to release worker")
            return search_positions_early(*args, **kwargs)

        manager = JobManager(
            chunk_size=64, search_functions={"baseline": search_positions, "early": controlled}
        )
        try:
            started = manager.submit(prepare_search(search_request()))
            self.assertTrue(entered.wait(5))
            self.assertFalse(manager.close(timeout=0))
            with self.assertRaises(ClosedError):
                manager.submit(prepare_search(search_request()))
            release.set()
            self.assertTrue(manager.close())
            self.assertEqual(manager.get(started["id"])["status"], "cancelled")
        finally:
            release.set()
            manager.close()


if __name__ == "__main__":
    unittest.main()

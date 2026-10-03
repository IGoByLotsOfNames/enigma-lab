# Path: working/tests/test_benchmark_search.py
"""Benchmark protocol tests using synthetic receipts and injected clocks only.

These tests do not run a latency experiment or create measured-performance claims.
"""

import contextlib
import copy
import importlib.util
import io
import math
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "experiments/search-latency-v1/benchmark_search.py"
SPEC = importlib.util.spec_from_file_location("benchmark_search_test_support", SCRIPT)
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


def fixture_bundle():
    """Protocol-shaped synthetic data; ciphertexts are deliberately not cipher evidence."""
    case_ids = ["basic-B-5", "ambiguous-B-1", "early-B-97", "late-B-97"]
    cases = []
    for case_id, length, crib_length, offset in zip(
        case_ids, [5, 1, 97, 97], [5, 1, 12, 12], [0, 0, 0, 85], strict=True
    ):
        cases.append(
            {
                "id": case_id,
                "settings": {
                    "rotors": ["I", "II", "III"],
                    "reflector": "B",
                    "rings": "AAA",
                    "positions": "AAA",
                    "plugboard": [],
                },
                "ciphertext": "B" * length,
                "crib": "A" * crib_length,
                "offset": offset,
                "known_initial_windows": "AAA",
            }
        )
    plan = {
        "schema_version": 1,
        "benchmark": "complete-start-position-search",
        "schedule_seed": 1729,
        "warmup_calls": 1,
        "timed_calls": 2,
        "processes_per_implementation_case": 5,
        "subprocess_timeout_seconds": 600,
        "implementations": ["baseline", "early"],
        "case_ids": case_ids,
        "schedule": BENCH.make_schedule(case_ids),
    }
    return {
        "plan": plan,
        "inputs": {"schema_version": 1, "cases": cases},
        "lock": {"lock_sha256": "a" * 64, "files": {}},
    }


def fake_payload(case, implementation):
    length = (
        len(case["ciphertext"])
        if implementation == "baseline"
        else case["offset"] + len(case["crib"])
    )
    return {
        "complete": True,
        "global_domain": True,
        "domain_size": 17576,
        "candidates_checked": 17576,
        "characters_transformed": 17576 * length,
        "searched_positions": None,
        "matches": ["AAA"],
        "ciphertext": case["ciphertext"],
        "crib": case["crib"],
        "offset": case["offset"],
        "settings": {
            name: value for name, value in case["settings"].items() if name != "positions"
        },
        "domain_description": "All 17,576 A-Z starting-position triples",
    }


def fake_job(job, elapsed_ms=2):
    return {
        "job": job,
        "status": "complete",
        "warmup_calls": 1,
        "all_results_verified": True,
        "samples": [
            {
                "call": index,
                "elapsed_ns": int(elapsed_ms * 1_000_000),
                "elapsed_ms": elapsed_ms,
                "verified": True,
            }
            for index in (1, 2)
        ],
    }


class PlanAndScheduleTests(unittest.TestCase):
    def test_frozen_schedule_is_complete_adjacent_and_balanced(self):
        bundle = fixture_bundle()
        plan = bundle["plan"]
        BENCH.validate_plan(plan, bundle["inputs"])
        schedule = plan["schedule"]
        self.assertEqual(len(schedule), 40)
        self.assertEqual(len({job["job_id"] for job in schedule}), 40)
        self.assertEqual(
            len({(job["case_id"], job["replicate"], job["implementation"]) for job in schedule}), 40
        )
        first_counts = {"baseline": 0, "early": 0}
        case_counts = {case_id: {"baseline": 0, "early": 0} for case_id in plan["case_ids"]}
        for index in range(0, 40, 2):
            first, second = schedule[index : index + 2]
            self.assertEqual(
                (first["case_id"], first["replicate"]), (second["case_id"], second["replicate"])
            )
            self.assertEqual(
                {first["implementation"], second["implementation"]}, {"baseline", "early"}
            )
            first_counts[first["implementation"]] += 1
            case_counts[first["case_id"]][first["implementation"]] += 1
        self.assertEqual(first_counts, {"baseline": 10, "early": 10})
        self.assertTrue(all(sorted(counts.values()) == [2, 3] for counts in case_counts.values()))
        self.assertEqual(schedule, BENCH.make_schedule(plan["case_ids"]))

    def test_plan_rejects_changed_protocol_or_duplicate_jobs(self):
        for field, value in (
            ("warmup_calls", 0),
            ("warmup_calls", True),
            ("timed_calls", 3),
            ("schedule_seed", 1),
            ("subprocess_timeout_seconds", 0),
            ("implementations", ["baseline"]),
            ("case_ids", ["same"] * 4),
        ):
            bundle = fixture_bundle()
            bundle["plan"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                BENCH.validate_plan(bundle["plan"], bundle["inputs"])
        bundle = fixture_bundle()
        bundle["plan"]["schedule"][-1] = bundle["plan"]["schedule"][0]
        with self.assertRaisesRegex(ValueError, "Schedule"):
            BENCH.validate_plan(bundle["plan"], bundle["inputs"])

    def test_input_shapes_and_known_key_requirements_are_checked(self):
        changes = [
            ("offset", True),
            ("offset", 1),
            ("ciphertext", "AAAA!"),
            ("crib", "A"),
            ("known_initial_windows", "XYZ"),
            ("independent_expected_matches", ["XYZ"]),
        ]
        for field, value in changes:
            bundle = fixture_bundle()
            bundle["inputs"]["cases"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                BENCH.validate_plan(bundle["plan"], bundle["inputs"])
        bundle = fixture_bundle()
        bundle["inputs"]["cases"][0]["settings"]["plugboard"] = ["AB", "AC"]
        with self.assertRaises(ValueError):
            BENCH.validate_plan(bundle["plan"], bundle["inputs"])

    def test_extra_documentary_metadata_is_permitted(self):
        bundle = fixture_bundle()
        bundle["plan"]["property"] = "Fixture for protocol validation only."
        bundle["inputs"]["cases"][0]["provenance"] = {"kind": "synthetic-test-only"}
        BENCH.validate_plan(bundle["plan"], bundle["inputs"])


class LockTests(unittest.TestCase):
    def create_locked_tree(self, root):
        experiment = root / "experiments/search-latency-v1"
        experiment.mkdir(parents=True)
        names = [
            *BENCH.APP_FILES,
            *(
                f"experiments/search-latency-v1/{name}"
                for name in ("benchmark_search.py", "plan.json", "inputs.json")
            ),
        ]
        files = {}
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic locked content\n", encoding="utf-8")
            files[name] = BENCH.digest(path)
        lock = {"schema_version": 1, "algorithm": "sha256", "files": files}
        BENCH.write_json(experiment / "lock.json", lock)
        return experiment, lock

    def test_hash_lock_accepts_identical_bytes_and_refuses_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            experiment, _ = self.create_locked_tree(root)
            self.assertEqual(len(BENCH.verify_lock(root, experiment)["files"]), 10)
            (root / BENCH.APP_FILES[0]).write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Hash drift"):
                BENCH.verify_lock(root, experiment)

    def test_missing_required_file_and_parent_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            experiment, lock = self.create_locked_tree(root)
            missing = copy.deepcopy(lock)
            del missing["files"][BENCH.APP_FILES[0]]
            BENCH.write_json(experiment / "lock.json", missing)
            with self.assertRaisesRegex(ValueError, "omits"):
                BENCH.verify_lock(root, experiment)
            for name in (
                "../outside",
                "/absolute",
                "C:/outside",
                "nested/../file",
                "nested\\file",
                "nested//file",
            ):
                invalid = copy.deepcopy(lock)
                invalid["files"][name] = "a" * 64
                BENCH.write_json(experiment / "lock.json", invalid)
                with self.subTest(path=name), self.assertRaises(ValueError):
                    BENCH.verify_lock(root, experiment)


class EvidenceAndStatisticsTests(unittest.TestCase):
    def test_result_counters_and_known_key_membership_are_required(self):
        case = fixture_bundle()["inputs"]["cases"][2]
        baseline, early = fake_payload(case, "baseline"), fake_payload(case, "early")
        BENCH.validate_result(baseline, case, "baseline")
        BENCH.validate_result(early, case, "early")
        self.assertEqual(BENCH.semantic_result(baseline), BENCH.semantic_result(early))
        for field, value in (
            ("matches", []),
            ("matches", ["AAA", "AAA"]),
            ("complete", False),
            ("candidates_checked", 17575),
            ("characters_transformed", 17576 - 1),
        ):
            invalid = copy.deepcopy(early)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                BENCH.validate_result(invalid, case, "early")
        invalid = copy.deepcopy(early)
        invalid["settings"]["rings"] = "ZZZ"
        with self.assertRaisesRegex(ValueError, "known settings"):
            BENCH.validate_result(invalid, case, "early")

    def test_result_settings_accept_canonicalized_plug_pairs(self):
        case = fixture_bundle()["inputs"]["cases"][0]
        case["settings"]["plugboard"] = ["ZY", "BA"]
        payload = fake_payload(case, "baseline")
        payload["settings"]["plugboard"] = ["AB", "YZ"]
        BENCH.validate_result(payload, case, "baseline")

    def test_known_sample_statistics_use_ddof_one_without_filtering(self):
        stats = BENCH.sample_statistics([1, 2, 3, 4, 5])
        self.assertEqual(
            (stats["n"], stats["mean"], stats["median"], stats["sample_variance"], stats["ddof"]),
            (5, 3, 3, 2.5, 1),
        )
        self.assertAlmostEqual(stats["sample_sd"], math.sqrt(2.5))
        self.assertEqual(BENCH.sample_statistics([-1, 0, 1])["mean"], 0)
        for values in ([], [1], [1, float("nan")], [1, float("inf")], [True, 2]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                BENCH.sample_statistics(values)

    def test_aggregation_pairs_process_means_and_never_pools_calls(self):
        plan = fixture_bundle()["plan"]
        jobs = []
        for job in plan["schedule"]:
            base = job["replicate"]
            jobs.append(
                fake_job(job, elapsed_ms=base * (2 if job["implementation"] == "baseline" else 1))
            )
        summary = BENCH.aggregate_results(plan, jobs)
        for case in summary.values():
            self.assertEqual(case["baseline"]["process_means_ms"], [2, 4, 6, 8, 10])
            self.assertEqual(case["early"]["process_means_ms"], [1, 2, 3, 4, 5])
            self.assertEqual(case["paired_early_minus_baseline_ms"]["values"], [-1, -2, -3, -4, -5])
            self.assertEqual(case["paired_baseline_over_early_ratios"]["values"], [2] * 5)
            self.assertEqual(case["early"]["n"], 5)

    def test_failed_partial_reordered_or_unverified_jobs_cannot_be_aggregated(self):
        plan = fixture_bundle()["plan"]
        good = [fake_job(job) for job in plan["schedule"]]
        bad_sets = [good[:-1], list(reversed(good)), good[:-1] + [good[0]]]
        for field, value in (
            ("status", "failed"),
            ("all_results_verified", False),
            ("samples", []),
        ):
            jobs = copy.deepcopy(good)
            jobs[0][field] = value
            bad_sets.append(jobs)
        jobs = copy.deepcopy(good)
        jobs[0]["samples"][0]["verified"] = False
        bad_sets.append(jobs)
        for jobs in bad_sets:
            with self.subTest(first=jobs[0]["job"]), self.assertRaises(ValueError):
                BENCH.aggregate_results(plan, jobs)


class SyntheticOrchestrationTests(unittest.TestCase):
    def make_worker_args(self, directory):
        bundle = fixture_bundle()
        job = bundle["plan"]["schedule"][0]
        case = next(case for case in bundle["inputs"]["cases"] if case["id"] == job["case_id"])
        expected = fake_payload(case, job["implementation"])
        evidence = {
            "status": "complete",
            "lock_sha256": bundle["lock"]["lock_sha256"],
            "cases": {case["id"]: {"results": {job["implementation"]: expected}}},
        }
        evidence_path = Path(directory) / "preflight.json"
        BENCH.write_json(evidence_path, evidence)
        args = SimpleNamespace(
            experiment=Path(directory),
            job_id=job["job_id"],
            preflight=evidence_path,
            preflight_sha256=BENCH.digest(evidence_path),
            output=Path(directory) / "worker.json",
        )
        return args, bundle, expected

    def test_worker_uses_one_untimed_warmup_and_two_injected_clock_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            args, bundle, expected = self.make_worker_args(directory)
            fake_search = Mock(side_effect=lambda *unused: copy.deepcopy(expected))
            checkpoints = []
            original_write = BENCH.write_json

            def checkpoint(path, value):
                checkpoints.append(copy.deepcopy(value))
                original_write(path, value)

            with (
                patch.object(BENCH, "load_bundle", return_value=bundle),
                patch.object(
                    BENCH,
                    "machine_functions",
                    return_value=(
                        lambda **unused: object(),
                        {"baseline": fake_search, "early": fake_search},
                    ),
                ),
                patch.object(BENCH, "result_payload", side_effect=lambda value: value),
                patch.object(
                    BENCH.time,
                    "perf_counter_ns",
                    side_effect=[1_000_000, 3_000_000, 10_000_000, 14_000_000],
                ) as clock,
                patch.object(BENCH, "write_json", side_effect=checkpoint),
            ):
                self.assertEqual(BENCH.worker(args), 0)
            result = BENCH.read_json(args.output)
            self.assertEqual(fake_search.call_count, 3)
            self.assertEqual(clock.call_count, 4)
            self.assertEqual([sample["elapsed_ms"] for sample in result["samples"]], [2, 4])
            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["validated_result"], expected)
            self.assertTrue(result["timing_complete"])
            self.assertEqual([len(item["samples"]) for item in checkpoints], [0, 0, 1, 2, 2])
            self.assertEqual(checkpoints[1]["warmup_calls"], 1)
            self.assertTrue(checkpoints[2]["samples"][0]["verified"])

    def test_worker_preserves_a_failed_synthetic_sample_without_success(self):
        with tempfile.TemporaryDirectory() as directory:
            args, bundle, expected = self.make_worker_args(directory)
            invalid = copy.deepcopy(expected)
            invalid["matches"] = []
            fake_search = Mock(side_effect=[expected, invalid])
            with (
                patch.object(BENCH, "load_bundle", return_value=bundle),
                patch.object(
                    BENCH,
                    "machine_functions",
                    return_value=(
                        lambda **unused: object(),
                        {"baseline": fake_search, "early": fake_search},
                    ),
                ),
                patch.object(BENCH, "result_payload", side_effect=lambda value: value),
                patch.object(BENCH.time, "perf_counter_ns", side_effect=[1, 1001]),
            ):
                self.assertEqual(BENCH.worker(args), 1)
            result = BENCH.read_json(args.output)
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["all_results_verified"])
            self.assertEqual(len(result["samples"]), 1)
            self.assertFalse(result["samples"][0]["verified"])
            self.assertTrue(result["timing_collected"])
            self.assertFalse(result["timing_complete"])

    def test_child_is_terminated_and_waited_after_timeout_or_interruption(self):
        for failure in (subprocess.TimeoutExpired("synthetic", 1), KeyboardInterrupt()):
            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                process = Mock()
                process.wait.side_effect = [failure, 0]
                process.poll.return_value = None
                with patch.object(BENCH.subprocess, "Popen", return_value=process):
                    with self.assertRaises(type(failure)):
                        BENCH.run_job(
                            Path(directory),
                            Path(directory),
                            {"job_id": "job-01"},
                            Path(directory) / "preflight.json",
                            "a" * 64,
                            1,
                        )
                process.terminate.assert_called_once()
                self.assertEqual(process.wait.call_count, 2)

    def test_controller_failure_keeps_partial_job_without_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            experiment = root / "experiment"
            experiment.mkdir()
            bundle = fixture_bundle()
            completed = fake_job(bundle["plan"]["schedule"][0])
            completed["lock_sha256"] = bundle["lock"]["lock_sha256"]
            args = SimpleNamespace(
                experiment=experiment,
                command="run",
                power_mode="synthetic",
                power_source="synthetic",
                background_activity="synthetic",
            )

            def fake_run_job(*arguments):
                if arguments[2]["job_id"] == "job-01":
                    completed["preflight_sha256"] = arguments[4]
                    return completed
                raise subprocess.TimeoutExpired("synthetic child", 1)

            with (
                patch.object(BENCH, "WORKING_ROOT", root),
                patch.object(BENCH, "load_bundle", return_value=bundle),
                patch.object(BENCH, "preflight", return_value=None),
                patch.object(BENCH, "run_job", side_effect=fake_run_job),
                patch.object(
                    BENCH.time,
                    "perf_counter_ns",
                    side_effect=AssertionError("Real timing is forbidden in this test"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(BENCH.controller(args), 1)
            results = list((experiment / "results").glob("*/results.json"))
            self.assertEqual(len(results), 1)
            receipt = BENCH.read_json(results[0])
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(len(receipt["jobs"]), 1)
            self.assertNotIn("summary", receipt)
            self.assertEqual(receipt["active_job"]["job_id"], "job-02")
            self.assertTrue(receipt["timing_collected"])
            self.assertFalse(receipt["timing_complete"])

    def test_validate_command_boundary_never_starts_a_timer_or_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            experiment = root / "experiment"
            experiment.mkdir()
            bundle = fixture_bundle()
            with (
                patch.object(BENCH, "WORKING_ROOT", root),
                patch.object(BENCH, "load_bundle", return_value=bundle),
                patch.object(BENCH, "preflight", return_value=None),
                patch.object(
                    BENCH, "run_job", side_effect=AssertionError("No worker allowed")
                ) as run_job,
                patch.object(
                    BENCH.time, "perf_counter_ns", side_effect=AssertionError("No timer allowed")
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(BENCH.main(["validate", str(experiment)]), 0)
            run_job.assert_not_called()
            receipt = BENCH.read_json(
                next((experiment / "validation-results").glob("*/results.json"))
            )
            self.assertEqual(receipt["status"], "complete")
            self.assertFalse(receipt["timing_collected"])
            self.assertFalse(receipt["timing_complete"])


if __name__ == "__main__":
    unittest.main()

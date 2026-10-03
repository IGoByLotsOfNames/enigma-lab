# Path: working/experiments/search-latency-v1/benchmark_search.py
"""Locked complete-domain search experiment; only the explicit run command times calls.

Validate produces untimed differential correctness evidence. Run repeats that
preflight, then launches the frozen schedule of fresh worker processes. Fixtures,
MachineKey construction, startup, warmup, checking and JSON are outside the timer.
Each timed call includes the search API's validation, domain construction, reset,
transformation and counters. Results describe process means, not request tails.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

WORKING_ROOT = Path(__file__).resolve().parents[2]
POSITION_COUNT = 26**3
IMPLEMENTATIONS = ["baseline", "early"]
APP_FILES = [
    "enigma_lab/__init__.py",
    "enigma_lab/__main__.py",
    "enigma_lab/cli.py",
    "enigma_lab/engine.py",
    "enigma_lab/search.py",
    "enigma_lab/search_early.py",
    "enigma_lab/specs.py",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def make_schedule(case_ids, seed=1729):
    """Keep implementation pairs adjacent; balance first order 3/2 per case, 10/10 overall."""
    pairs = []
    for case_index, case_id in enumerate(case_ids):
        for replicate in range(1, 6):
            order = IMPLEMENTATIONS if (case_index + replicate) % 2 == 0 else IMPLEMENTATIONS[::-1]
            pairs.append((case_id, replicate, order))
    random.Random(seed).shuffle(pairs)
    schedule = []
    for case_id, replicate, order in pairs:
        for implementation in order:
            schedule.append(
                {
                    "job_id": f"job-{len(schedule) + 1:02d}",
                    "case_id": case_id,
                    "replicate": replicate,
                    "implementation": implementation,
                }
            )
    return schedule


def ascii_word(value, size=None):
    return (
        isinstance(value, str)
        and bool(re.fullmatch(r"[A-Z]+", value))
        and (size is None or len(value) == size)
    )


def validate_plan(plan, inputs):
    require(isinstance(plan, dict) and isinstance(inputs, dict), "Plan and inputs must be objects.")
    fixed = {
        "schema_version": 1,
        "benchmark": "complete-start-position-search",
        "schedule_seed": 1729,
        "warmup_calls": 1,
        "timed_calls": 2,
        "processes_per_implementation_case": 5,
        "implementations": IMPLEMENTATIONS,
    }
    for name, expected in fixed.items():
        require(plan.get(name) == expected, f"Unsupported plan field: {name}")
        if isinstance(expected, int):
            require(integer(plan.get(name)), f"Plan {name} must be an integer.")
    timeout = plan.get("subprocess_timeout_seconds")
    require(integer(timeout) and 1 <= timeout <= 3600, "Worker timeout must be 1..3600 seconds.")
    require(inputs.get("schema_version") == 1, "Unsupported input schema.")
    cases, case_ids = inputs.get("cases"), plan.get("case_ids")
    require(isinstance(cases, list) and len(cases) == 4, "Exactly four fixed cases are required.")
    require(
        isinstance(case_ids, list) and len(case_ids) == 4, "Exactly four case IDs are required."
    )
    require(
        all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9-]+", value) for value in case_ids),
        "Case IDs must be simple nonempty names.",
    )
    require(len(set(case_ids)) == 4, "Duplicate case IDs.")
    require(all(isinstance(case, dict) for case in cases), "Cases must be objects.")
    require([case.get("id") for case in cases] == case_ids, "Input case order must match the plan.")
    for case, (length, crib_length, offset) in zip(
        cases, [(5, 5, 0), (1, 1, 0), (97, 12, 0), (97, 12, 85)], strict=True
    ):
        require(ascii_word(case.get("ciphertext"), length), f"Invalid ciphertext: {case['id']}")
        require(ascii_word(case.get("crib"), crib_length), f"Invalid crib: {case['id']}")
        require(integer(case.get("offset")) and case["offset"] == offset, "Unexpected crib offset.")
        settings = case.get("settings")
        require(isinstance(settings, dict), "Settings must be an object.")
        require(
            set(settings) == {"rotors", "reflector", "rings", "positions", "plugboard"},
            "Settings must contain the complete declared key.",
        )
        rotors = settings["rotors"]
        require(
            isinstance(rotors, list)
            and len(rotors) == 3
            and all(
                isinstance(name, str) and name in {"I", "II", "III", "IV", "V"} for name in rotors
            )
            and len(set(rotors)) == 3,
            "Invalid rotor selection.",
        )
        require(settings["reflector"] in ("B", "C"), "Invalid reflector.")
        require(
            ascii_word(settings["rings"], 3) and ascii_word(settings["positions"], 3),
            "Invalid rings/windows.",
        )
        plugs = settings["plugboard"]
        require(
            isinstance(plugs, list)
            and len(plugs) <= 13
            and all(ascii_word(pair, 2) for pair in plugs),
            "Invalid plug pairs.",
        )
        require(len(set("".join(plugs))) == 2 * len(plugs), "Plug pairs overlap or self-pair.")
        require(ascii_word(case.get("known_initial_windows"), 3), "Missing known initial windows.")
        require(
            settings["positions"] == case["known_initial_windows"], "Known key windows disagree."
        )
        if "independent_expected_matches" in case:
            matches = case["independent_expected_matches"]
            require(
                isinstance(matches, list) and all(ascii_word(value, 3) for value in matches),
                "Invalid independent match list.",
            )
            require(
                matches == sorted(set(matches)), "Independent matches must be sorted and unique."
            )
            require(case["known_initial_windows"] in matches, "Independent matches omit known key.")
    require(
        plan.get("schedule") == make_schedule(case_ids, plan["schedule_seed"]),
        "Schedule differs from the complete balanced frozen design.",
    )


def verify_lock(root, experiment):
    root, experiment = Path(root).resolve(), Path(experiment).resolve()
    relative_experiment = experiment.relative_to(root).as_posix()
    lock_path = experiment / "lock.json"
    lock = read_json(lock_path)
    require(
        isinstance(lock, dict)
        and lock.get("schema_version") == 1
        and lock.get("algorithm") == "sha256",
        "Unsupported source lock.",
    )
    files = lock.get("files")
    require(isinstance(files, dict), "Lock files must be an object.")
    required = {
        *APP_FILES,
        *(
            f"{relative_experiment}/{name}"
            for name in ("plan.json", "inputs.json", "benchmark_search.py")
        ),
    }
    require(
        required <= set(files), "Lock omits required plan, inputs, benchmark or application files."
    )
    for relative, expected in files.items():
        require(
            isinstance(relative, str) and relative and "\\" not in relative and ":" not in relative,
            "Lock paths must be relative POSIX paths.",
        )
        parts = relative.split("/")
        require(
            not PurePosixPath(relative).is_absolute()
            and all(part not in ("", ".", "..") for part in parts),
            "Unsafe lock path.",
        )
        target = (root / relative).resolve()
        require(
            target.is_relative_to(root) and target.is_file(),
            f"Locked file is missing or escapes root: {relative}",
        )
        require(
            isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
            "Invalid SHA256 in lock.",
        )
        require(digest(target) == expected, f"Hash drift: {relative}")
    return {"lock_sha256": digest(lock_path), "files": files}


def load_bundle(experiment, expected_lock=None):
    experiment = Path(experiment).resolve()
    require(
        experiment.is_relative_to(WORKING_ROOT), "Experiment must be inside this working directory."
    )
    lock = verify_lock(WORKING_ROOT, experiment)
    if expected_lock is not None:
        require(lock["lock_sha256"] == expected_lock, "Lock changed during execution.")
    plan, inputs = read_json(experiment / "plan.json"), read_json(experiment / "inputs.json")
    validate_plan(plan, inputs)
    return {"plan": plan, "inputs": inputs, "lock": lock}


def machine_functions():
    # Import only after the source lock was checked by the caller.
    sys.path.insert(0, str(WORKING_ROOT))
    from enigma_lab.engine import MachineKey
    from enigma_lab.search import search_positions
    from enigma_lab.search_early import search_positions_early

    return MachineKey, {"baseline": search_positions, "early": search_positions_early}


def result_payload(result):
    return json.loads(json.dumps(asdict(result)))


def semantic_result(payload):
    return {key: value for key, value in payload.items() if key != "characters_transformed"}


def validate_result(payload, case, implementation):
    require(
        payload.get("complete") is True and payload.get("global_domain") is True,
        "Incomplete search result.",
    )
    require(
        payload.get("candidates_checked") == POSITION_COUNT
        and payload.get("domain_size") == POSITION_COUNT,
        "Search did not cover all 17,576 candidates.",
    )
    require(payload.get("searched_positions") is None, "Unexpected subset result.")
    for name in ("ciphertext", "crib", "offset"):
        require(payload.get(name) == case[name], f"Search result {name} disagrees with input.")
    settings = case["settings"]
    expected_settings = {
        "rotors": settings["rotors"],
        "reflector": settings["reflector"],
        "rings": settings["rings"],
        "plugboard": sorted("".join(sorted(pair)) for pair in settings["plugboard"]),
    }
    require(payload.get("settings") == expected_settings, "Search result known settings disagree.")
    matches = payload.get("matches")
    require(
        isinstance(matches, list) and all(ascii_word(value, 3) for value in matches),
        "Malformed matching positions.",
    )
    require(
        matches == sorted(set(matches)), "Matches must contain every unique match in domain order."
    )
    require(case["known_initial_windows"] in matches, "Known key missing from search result.")
    if "independent_expected_matches" in case:
        require(
            matches == case["independent_expected_matches"],
            "Independent complete match set disagrees.",
        )
    count = payload.get("characters_transformed")
    require(integer(count), "Transformation count must be an integer.")
    if implementation == "baseline":
        require(
            count == POSITION_COUNT * len(case["ciphertext"]),
            "Baseline transformation counter disagrees.",
        )
    else:
        require(implementation == "early", "Unknown implementation.")
        require(
            POSITION_COUNT * (case["offset"] + 1)
            <= count
            <= POSITION_COUNT * (case["offset"] + len(case["crib"])),
            "Early transformation counter is outside its bounds.",
        )


def platform_metadata():
    clock = time.get_clock_info("perf_counter")
    return {
        "python": sys.version,
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "timer": {
            "name": "perf_counter_ns",
            "implementation": clock.implementation,
            "resolution_seconds": clock.resolution,
            "monotonic": clock.monotonic,
            "adjustable": clock.adjustable,
        },
        "gc_enabled": gc.isenabled(),
        "gc_thresholds": list(gc.get_threshold()),
    }


def preflight(bundle, receipt, progress_path):
    key_type, implementations = machine_functions()
    for case in bundle["inputs"]["cases"]:
        print(f"Untimed preflight: {case['id']}", flush=True)
        key = key_type(**case["settings"])
        results = {}
        for name, function in implementations.items():
            payload = result_payload(
                function(key, case["ciphertext"], case["crib"], case["offset"])
            )
            validate_result(payload, case, name)
            results[name] = payload
        require(
            semantic_result(results["baseline"]) == semantic_result(results["early"]),
            "Baseline and early complete results disagree.",
        )
        receipt["cases"][case["id"]] = {
            "results": results,
            "basis": (
                "Independent complete expected match set, plus baseline/early agreement."
                if "independent_expected_matches" in case
                else "Baseline/early complete-domain differential agreement; independent oracle supports known-key message, not the full matching set."
            ),
        }
        write_json(progress_path, receipt)


def sample_statistics(values):
    require(len(values) >= 2, "Sample statistics require at least two observations.")
    require(
        all(
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
            for value in values
        ),
        "Samples must be finite numbers.",
    )
    variance = statistics.variance(values)
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "sample_sd": math.sqrt(variance),
        "sample_variance": variance,
        "minimum": min(values),
        "maximum": max(values),
        "ddof": 1,
    }


def aggregate_results(plan, jobs):
    require(len(jobs) == len(plan["schedule"]), "Incomplete jobs cannot be aggregated.")
    means = {}
    for expected, job in zip(plan["schedule"], jobs, strict=True):
        require(
            job.get("job") == expected and job.get("status") == "complete",
            "Failed, missing, reordered or duplicate job.",
        )
        require(
            job.get("warmup_calls") == plan["warmup_calls"]
            and job.get("all_results_verified") is True,
            "Worker verification is incomplete.",
        )
        samples = job.get("samples")
        require(
            isinstance(samples, list) and len(samples) == plan["timed_calls"],
            "Incomplete timed samples.",
        )
        for index, sample in enumerate(samples, 1):
            ns = sample.get("elapsed_ns")
            require(sample.get("call") == index and integer(ns) and ns > 0, "Invalid timer sample.")
            require(sample.get("elapsed_ms") == ns / 1_000_000, "Timer unit mismatch.")
            require(
                sample.get("verified") is True, "An unverified timing sample cannot be aggregated."
            )
        mean = statistics.fmean(sample["elapsed_ms"] for sample in samples)
        means[(expected["case_id"], expected["implementation"], expected["replicate"])] = mean
    require(len(means) == len(plan["schedule"]), "Duplicate implementation/case/replicate.")
    summaries = {}
    for case_id in plan["case_ids"]:
        baseline = [means[(case_id, "baseline", rep)] for rep in range(1, 6)]
        early = [means[(case_id, "early", rep)] for rep in range(1, 6)]
        delta = [e - b for b, e in zip(baseline, early, strict=True)]
        ratios = [b / e for b, e in zip(baseline, early, strict=True)]
        summaries[case_id] = {
            "baseline": {"process_means_ms": baseline, **sample_statistics(baseline)},
            "early": {"process_means_ms": early, **sample_statistics(early)},
            "paired_early_minus_baseline_ms": {"values": delta, **sample_statistics(delta)},
            "paired_baseline_over_early_ratios": {"values": ratios, **sample_statistics(ratios)},
        }
    return summaries


def worker(args):
    output = Path(args.output)
    receipt = {
        "schema_version": 1,
        "status": "running",
        "samples": [],
        "warmup_calls": 0,
        "all_results_verified": False,
        "timing_collected": False,
        "timing_complete": False,
    }
    exit_code = 1
    try:
        bundle = load_bundle(args.experiment)
        require(digest(args.preflight) == args.preflight_sha256, "Frozen preflight hash mismatch.")
        evidence = read_json(args.preflight)
        require(evidence.get("status") == "complete", "Preflight is incomplete.")
        require(
            evidence["lock_sha256"] == bundle["lock"]["lock_sha256"],
            "Preflight belongs to another source lock.",
        )
        matches = [job for job in bundle["plan"]["schedule"] if job["job_id"] == args.job_id]
        require(len(matches) == 1, "Unknown scheduled job.")
        job = matches[0]
        receipt["job"] = job
        case = next(case for case in bundle["inputs"]["cases"] if case["id"] == job["case_id"])
        key_type, implementations = machine_functions()
        function, key = implementations[job["implementation"]], key_type(**case["settings"])
        expected = evidence["cases"][case["id"]]["results"][job["implementation"]]
        gc.enable()
        receipt["metadata"] = platform_metadata()
        receipt["lock_sha256"] = evidence["lock_sha256"]
        receipt["preflight_sha256"] = args.preflight_sha256
        write_json(output, receipt)
        for _ in range(bundle["plan"]["warmup_calls"]):
            actual = result_payload(function(key, case["ciphertext"], case["crib"], case["offset"]))
            validate_result(actual, case, job["implementation"])
            require(actual == expected, "Warmup differs from frozen correctness evidence.")
            receipt["warmup_calls"] += 1
            write_json(output, receipt)
        for index in range(1, bundle["plan"]["timed_calls"] + 1):
            started = time.perf_counter_ns()
            result = function(key, case["ciphertext"], case["crib"], case["offset"])
            elapsed = time.perf_counter_ns() - started
            sample = {
                "call": index,
                "elapsed_ns": elapsed,
                "elapsed_ms": elapsed / 1_000_000,
                "verified": False,
            }
            receipt["samples"].append(sample)
            receipt["timing_collected"] = True
            actual = result_payload(result)
            validate_result(actual, case, job["implementation"])
            require(actual == expected, "Timed result differs from frozen correctness evidence.")
            require(elapsed > 0, "Nonpositive elapsed timer result.")
            sample["verified"] = True
            del result
            write_json(output, receipt)
        load_bundle(args.experiment, expected_lock=evidence["lock_sha256"])
        receipt["validated_result"] = expected
        receipt["all_results_verified"] = True
        receipt["timing_complete"] = True
        receipt["status"] = "complete"
        exit_code = 0
    except KeyboardInterrupt:
        receipt.update(status="interrupted", error="Worker interrupted.")
        exit_code = 130
    except Exception as exc:
        receipt.update(status="failed", error=f"{type(exc).__name__}: {exc}")
    receipt["finished_utc"] = datetime.now(UTC).isoformat()
    write_json(output, receipt)
    return exit_code


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_job(experiment, output, job, preflight_path, preflight_sha, timeout):
    result_path = output / f"{job['job_id']}.json"
    command = [
        sys.executable,
        "-B",
        "-X",
        "utf8",
        str(Path(__file__).resolve()),
        "_worker",
        str(experiment),
        "--job-id",
        job["job_id"],
        "--preflight",
        str(preflight_path),
        "--preflight-sha256",
        preflight_sha,
        "--output",
        str(result_path),
    ]
    with (
        (output / f"{job['job_id']}.stdout.txt").open("w", encoding="utf-8") as stdout,
        (output / f"{job['job_id']}.stderr.txt").open("w", encoding="utf-8") as stderr,
    ):
        process = subprocess.Popen(
            command, cwd=WORKING_ROOT, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr
        )
        try:
            code = process.wait(timeout=timeout)
        except (KeyboardInterrupt, subprocess.TimeoutExpired):
            stop_process(process)
            raise
    require(code == 0 and result_path.is_file(), f"Worker {job['job_id']} failed (exit {code}).")
    result = read_json(result_path)
    require(result.get("status") == "complete", f"Worker {job['job_id']} did not complete.")
    return result


def print_summary(summary):
    print("Complete-domain search: milliseconds per call; dispersion across five process means.")
    print("case | implementation | mean ms | median ms | sample SD ms | sample variance ms^2")
    for case_id, case in summary.items():
        for name in IMPLEMENTATIONS:
            stats = case[name]
            print(
                f"{case_id} | {name} | {stats['mean']:.6f} | {stats['median']:.6f} | {stats['sample_sd']:.6f} | {stats['sample_variance']:.6f}"
            )
        delta, ratio = (
            case["paired_early_minus_baseline_ms"],
            case["paired_baseline_over_early_ratios"],
        )
        print(
            f"  paired early-baseline mean {delta['mean']:.6f} ms (SD {delta['sample_sd']:.6f}); mean paired baseline/early ratio {ratio['mean']:.6f} (SD {ratio['sample_sd']:.6f})."
        )
    print(
        "Sample SD/variance use ddof=1. No outlier filtering; no pooled grand mean or request-tail claim."
    )


def controller(args):
    experiment = Path(args.experiment).resolve()
    require(
        experiment.is_relative_to(WORKING_ROOT) and experiment.is_dir(),
        "Experiment must be a directory inside working/.",
    )
    name = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = experiment / ("results" if args.command == "run" else "validation-results") / name
    output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema_version": 1,
        "status": "running",
        "command": args.command,
        "timing_collected": False,
        "timing_complete": False,
        "created_utc": datetime.now(UTC).isoformat(),
        "metadata": platform_metadata(),
        "reported_environment": {
            "power_mode": args.power_mode,
            "power_source": args.power_source,
            "background_activity": args.background_activity,
        },
        "jobs": [],
    }
    evidence = {"schema_version": 1, "status": "running", "timing_collected": False, "cases": {}}
    evidence_path = output / "preflight.json"
    code = 1
    try:
        bundle = load_bundle(experiment)
        receipt["lock"] = bundle["lock"]
        receipt["plan"] = bundle["plan"]
        receipt["inputs"] = bundle["inputs"]
        evidence["lock_sha256"] = bundle["lock"]["lock_sha256"]
        preflight(bundle, evidence, evidence_path)
        load_bundle(experiment, expected_lock=evidence["lock_sha256"])
        evidence.update(status="complete", finished_utc=datetime.now(UTC).isoformat())
        write_json(evidence_path, evidence)
        evidence_sha = digest(evidence_path)
        receipt["preflight_sha256"] = evidence_sha
        if args.command == "run":
            for index, job in enumerate(bundle["plan"]["schedule"], 1):
                receipt["active_job"] = job
                write_json(output / "results.json", receipt)
                print(
                    f"{index}/{len(bundle['plan']['schedule'])}: {job['case_id']} replicate {job['replicate']} {job['implementation']}",
                    flush=True,
                )
                result = run_job(
                    experiment,
                    output,
                    job,
                    evidence_path,
                    evidence_sha,
                    bundle["plan"]["subprocess_timeout_seconds"],
                )
                require(
                    result.get("lock_sha256") == evidence["lock_sha256"]
                    and result.get("preflight_sha256") == evidence_sha,
                    "Worker provenance differs.",
                )
                receipt["jobs"].append(result)
                receipt["timing_collected"] = True
                write_json(output / "results.json", receipt)
            load_bundle(experiment, expected_lock=evidence["lock_sha256"])
            receipt["summary"] = aggregate_results(bundle["plan"], receipt["jobs"])
        receipt.pop("active_job", None)
        receipt.update(
            status="complete",
            timing_collected=args.command == "run",
            timing_complete=args.command == "run",
        )
        code = 0
    except KeyboardInterrupt:
        receipt.update(
            status="interrupted",
            error="Interrupted; partial jobs are retained without aggregate statistics.",
        )
        code = 130
    except Exception as exc:
        receipt.update(status="failed", error=f"{type(exc).__name__}: {exc}")
    if evidence["status"] != "complete":
        evidence.update(
            status=receipt["status"], error=receipt.get("error", "Preflight incomplete.")
        )
        write_json(evidence_path, evidence)
    receipt["finished_utc"] = datetime.now(UTC).isoformat()
    if receipt["status"] != "complete":
        receipt.pop("summary", None)
        receipt["timing_complete"] = False
        receipt["timing_scope"] = (
            "Failed/interrupted run. Retained raw worker samples are partial evidence, never a completed timing comparison."
        )
        for worker_path in output.glob("job-*.json"):
            try:
                receipt["timing_collected"] = receipt["timing_collected"] or bool(
                    read_json(worker_path).get("samples")
                )
            except (OSError, ValueError):
                pass
        print(receipt["error"], file=sys.stderr)
    write_json(output / "results.json", receipt)
    if code == 0 and "summary" in receipt:
        print_summary(receipt["summary"])
    elif code == 0:
        print("Untimed correctness preflight complete. No latency measurements were collected.")
    print(f"Evidence: {output}")
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "run"):
        command = commands.add_parser(name)
        command.add_argument("experiment", type=Path)
        command.add_argument("--power-mode", default="not reported")
        command.add_argument("--power-source", default="not reported")
        command.add_argument("--background-activity", default="not reported")
    internal = commands.add_parser("_worker", help=argparse.SUPPRESS)
    internal.add_argument("experiment", type=Path)
    internal.add_argument("--job-id", required=True)
    internal.add_argument("--preflight", type=Path, required=True)
    internal.add_argument("--preflight-sha256", required=True)
    internal.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        return worker(args) if args.command == "_worker" else controller(args)
    except (ValueError, OSError) as exc:
        print(f"Experiment refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

# Path: enigma_demo/jobs.py
"""One cooperative, bounded background search at a time.

The UI invokes the existing search functions on 64-position subsets so progress,
cancellation and a deadline can be checked between calls. These are different
call boundaries from the frozen full-domain benchmark: UI execution is not a
new benchmark and reports no search-time performance claim. Cancellation and
timeouts cannot interrupt an in-progress subset call.
"""

import copy
import math
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import asdict, dataclass, field

from enigma_lab.search import (
    POSITION_COUNT,
    SearchResult,
    SearchSettings,
    search_positions,
    validate_candidate_positions,
)
from enigma_lab.search_early import search_positions_early

from .service import SearchRequest


class BusyError(RuntimeError):
    """A running search already owns the single worker slot."""


class ClosedError(RuntimeError):
    """The job manager is shutting down."""


@dataclass
class _Job:
    request: SearchRequest
    snapshot: dict
    cancel: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


class JobManager:
    def __init__(
        self,
        *,
        chunk_size=64,
        timeout_seconds=60.0,
        max_jobs=8,
        search_functions=None,
        clock=time.monotonic,
    ):
        if type(chunk_size) is not int or not 1 <= chunk_size <= POSITION_COUNT:
            raise ValueError("chunk_size must be between 1 and 17,576.")
        if type(max_jobs) is not int or not 1 <= max_jobs <= 8:
            raise ValueError("max_jobs must be between 1 and 8.")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be finite and positive.")
        self.chunk_size = chunk_size
        self.timeout_seconds = timeout_seconds
        self.max_jobs = max_jobs
        self._functions = (
            {"baseline": search_positions, "early": search_positions_early}
            if search_functions is None
            else dict(search_functions)
        )
        if set(self._functions) != {"baseline", "early"}:
            raise ValueError("Both search strategies are required.")
        if not all(callable(function) for function in self._functions.values()) or not callable(
            clock
        ):
            raise ValueError("Search strategies and clock must be callable.")
        self._clock = clock
        self._jobs = OrderedDict()
        self._lock = threading.Lock()
        self._closed = False

    def submit(self, request: SearchRequest) -> dict:
        if not isinstance(request, SearchRequest):
            raise ValueError("Use a validated SearchRequest.")
        with self._lock:
            if self._closed:
                raise ClosedError("The application is shutting down.")
            if any(job.snapshot["status"] == "running" for job in self._jobs.values()):
                raise BusyError("A search is already running. Wait for it or cancel it first.")
            while len(self._jobs) >= self.max_jobs:
                self._jobs.popitem(last=False)
            job_id = uuid.uuid4().hex
            job = _Job(
                request,
                {
                    "id": job_id,
                    "status": "running",
                    "strategy": request.strategy,
                    "candidates_checked": 0,
                    "domain_size": POSITION_COUNT,
                    "characters_transformed": 0,
                    "matches": [],
                    "partial_matches_unverified": True,
                    "cancel_requested": False,
                    "result": None,
                    "error": None,
                },
            )
            job.thread = threading.Thread(target=self._run, args=(job,), daemon=True)
            self._jobs[job_id] = job
            initial = copy.deepcopy(job.snapshot)
            try:
                job.thread.start()
            except Exception:
                del self._jobs[job_id]
                raise
            return initial

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return copy.deepcopy(job.snapshot) if job else None

    def cancel(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            if job.snapshot["status"] == "running":
                job.cancel.set()
                job.snapshot["cancel_requested"] = True
            return copy.deepcopy(job.snapshot)

    def _stop_reason(self, job, deadline):
        if job.cancel.is_set():
            return "cancelled"
        if self._clock() >= deadline:
            return "timed_out"
        return None

    def _finish(self, job, status, error=None):
        with self._lock:
            job.snapshot["status"] = status
            job.snapshot["error"] = error

    def _run(self, job):
        request = job.request
        try:
            deadline = self._clock() + self.timeout_seconds
            domain = validate_candidate_positions(None)
            for first in range(0, len(domain), self.chunk_size):
                reason = self._stop_reason(job, deadline)
                if reason:
                    self._finish(job, reason)
                    return
                chunk = domain[first : first + self.chunk_size]
                result = self._functions[request.strategy](
                    request.key, request.ciphertext, request.crib, request.offset, positions=chunk
                )
                if (
                    not result.complete
                    or result.candidates_checked != len(chunk)
                    or result.domain_size != len(chunk)
                    or len(set(result.matches)) != len(result.matches)
                    or not set(result.matches).issubset(chunk)
                    or not 0
                    <= result.characters_transformed
                    <= len(chunk) * len(request.ciphertext)
                ):
                    raise ValueError("The search function returned an incomplete subset.")
                with self._lock:
                    job.snapshot["candidates_checked"] += result.candidates_checked
                    job.snapshot["characters_transformed"] += result.characters_transformed
                    job.snapshot["matches"].extend(result.matches)
            reason = self._stop_reason(job, deadline)
            if reason:
                self._finish(job, reason)
                return
            with self._lock:
                if job.cancel.is_set():
                    job.snapshot["status"] = "cancelled"
                    return
                snapshot = job.snapshot
                if snapshot["candidates_checked"] != POSITION_COUNT:
                    raise ValueError("Search did not cover the full candidate domain.")
                complete = SearchResult(
                    matches=tuple(snapshot["matches"]),
                    candidates_checked=snapshot["candidates_checked"],
                    characters_transformed=snapshot["characters_transformed"],
                    complete=True,
                    domain_size=POSITION_COUNT,
                    global_domain=True,
                    domain_description="All 17,576 A-Z starting-position triples",
                    searched_positions=None,
                    ciphertext=request.ciphertext,
                    crib=request.crib,
                    offset=request.offset,
                    settings=SearchSettings(
                        rotors=request.key.rotors,
                        reflector=request.key.reflector,
                        rings=request.key.rings,
                        plugboard=request.key.plugboard,
                    ),
                )
                snapshot["result"] = asdict(complete)
                snapshot["partial_matches_unverified"] = False
                snapshot["status"] = "complete"
        except Exception:
            # Avoid leaking input text, file paths or tracebacks into responses/logs.
            self._finish(
                job, "failed", "The search could not finish. No complete result is available."
            )

    def close(self, timeout=5.0) -> bool:
        """Request cancellation, join workers, and report whether all stopped."""
        with self._lock:
            self._closed = True
            threads = []
            for job in self._jobs.values():
                if job.snapshot["status"] == "running":
                    job.cancel.set()
                    job.snapshot["cancel_requested"] = True
                if job.thread is not None:
                    threads.append(job.thread)
        deadline = time.monotonic() + max(0.0, timeout)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(max(0.0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in threads)

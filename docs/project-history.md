# Project history

## The original idea

I wanted to explore whether modern computing could help me understand and solve
Enigma, inspired by the contrast with the tools available to Alan Turing. That
curiosity led to a personal Python transformation and search prototype.

The [preserved original source](../history/original-prototype.py.txt) is unfinished.
It is included as a readable historical appendix and is not imported by the application. Its exact creation date and successful
recovery of any historical message have not been established. My motivation is
part of the project's history; it is not evidence that I reproduced wartime
cryptanalysis or recovered an unknown Enigma key.

## Revisiting the implementation

A useful lesson emerged from the original: encrypting and then reversing the
result can succeed even when both directions share the same mistake. Its forward
rotor calculation shifted into rotor coordinates without shifting back out, while
the reverse calculation undid that same mapping. Under the closest intended
all-A configuration, it produced `UDHLX` for `AAAAA`; the corrected implementation
agrees with the saved reference output `BDZGO`.

The revision establishes one coordinate system, derives inverse wiring from
forward permutations, makes the pre-key stepping decision explicit, and separates
immutable settings from moving rotor state. Independent message vectors and
mechanical traces test the intended behaviour instead of relying on round trips.

## A bounded search, then a visible workbench

The search question is deliberately narrower than recovering an arbitrary key:
with the other settings and crib alignment known, check all 17,576 starting
window triples and retain every matching one. A separate early-rejection strategy
keeps the same complete result while avoiding unnecessary work within a candidate.
The measured benefit depends on the workload; all four cases, including the
slower observed cases, remain in the [measurement record](../experiments/search-latency-v1/MEASURED_RESULTS.txt).

The local workbench shares the Python engine with the CLI. It displays rotor
movement and signal traces, and gives long searches explicit progress,
cancellation and incomplete-result states. It does not implement a second cipher
in JavaScript. The [design notes](../DESIGN_NOTES.txt) describe the reasoning behind
those boundaries.

Codex assisted the recent implementation, testing and documentation. The original
idea and early prototype were mine. The current tests and measurements belong to
the revision, not to an undocumented historical success or a comparison with
wartime hardware.

## Evidence boundaries

| Aspect | Basis |
|---|---|
| Original motivation | My account of the personal project |
| Original implementation | Preserved unfinished Python source; not part of the running application |
| Current machine behaviour | Structural tests, published vectors and saved independent-software reference cases |
| Starting-window recovery | Complete enumeration of the documented known-other-settings domain |
| Search latency | One recorded controlled run, four workloads, 40 fresh workers and 80 timed calls |
| Physical-machine fidelity across every setting | Not established by the available software references |
| Historical message recovery or comparison with wartime machines | Not claimed |

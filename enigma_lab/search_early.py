# Path: enigma_lab/search_early.py
"""Complete initial-position search with early rejection of crib mismatches.

Correctness: a candidate is rejected only after a decrypted character disagrees
with its required aligned crib character. Later characters cannot repair that
disagreement. A candidate matches exactly when every crib character agrees;
characters beyond the crib do not affect this predicate. Before the crib, every
prefix character is still transformed through the public machine API, preserving
the baseline's keypress sequence, including turnover and double stepping. Each
candidate resets its state, and the entire domain is visited even after a match.

For D candidates, N ciphertext letters, M crib letters and offset O, validation
takes O(N + M + D) work and cipher work is at most D * (O + M) keypresses. It is
at least D * (O + 1), since the nonempty crib requires its first comparison.
Normalized inputs, the candidate domain and matches occupy O(N + M + D) storage.
No full candidate plaintext is materialized. These are algorithmic bounds, not
measured speed or memory claims. A late crib can eliminate the work saving, and
per-character public-API validation adds overhead versus the baseline's bulk
process call. The unchanged baseline remains available in search.py.
"""

from collections.abc import Iterable

from .engine import Machine, MachineKey, normalize_text
from .search import (
    POSITION_COUNT,
    SearchResult,
    SearchSettings,
    validate_candidate_positions,
)


def search_positions_early(
    key: MachineKey,
    ciphertext: str,
    crib: str,
    offset: int = 0,
    positions: Iterable[str] | None = None,
) -> SearchResult:
    """Return all matches under the same validated contract as search_positions.

    The supplied key's starting positions are ignored. Each candidate supplies its
    own initial positions; all other key settings are fixed. Ciphertext and crib
    must contain ASCII letters only, with case normalization. Full inputs and the
    entire finite domain are validated before any candidate is transformed, even
    when their unused suffix would be skipped during search.

    characters_transformed counts successful public key_press calls, including the
    offset prefix and the first disagreeing character. Completion covers the full
    declared domain; interruption propagates without returning a partial result.
    """
    if not isinstance(key, MachineKey):
        raise ValueError("key must be a MachineKey")
    ciphertext = normalize_text(ciphertext, allow_empty=False)
    crib = normalize_text(crib, allow_empty=False)
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a nonnegative integer")
    if offset + len(crib) > len(ciphertext):
        raise ValueError("the crib must fit within the ciphertext at the supplied offset")
    domain = validate_candidate_positions(positions)

    machine = Machine(key)
    matches = []
    candidates_checked = 0
    characters_transformed = 0
    for start in domain:
        machine.reset(start)
        for index in range(offset):
            machine.key_press(ciphertext[index])
            characters_transformed += 1
        for index, expected in enumerate(crib, start=offset):
            actual = machine.key_press(ciphertext[index])
            characters_transformed += 1
            if actual != expected:
                break
        else:
            matches.append(start)
        candidates_checked += 1

    global_domain = len(domain) == POSITION_COUNT
    return SearchResult(
        matches=tuple(matches),
        candidates_checked=candidates_checked,
        characters_transformed=characters_transformed,
        complete=True,
        domain_size=len(domain),
        global_domain=global_domain,
        domain_description=(
            "All 17,576 A-Z starting-position triples"
            if global_domain
            else f"Supplied {len(domain)} unique starting-position triples"
        ),
        searched_positions=None if global_domain else domain,
        ciphertext=ciphertext,
        crib=crib,
        offset=offset,
        settings=SearchSettings(
            rotors=key.rotors,
            reflector=key.reflector,
            rings=key.rings,
            plugboard=key.plugboard,
        ),
    )

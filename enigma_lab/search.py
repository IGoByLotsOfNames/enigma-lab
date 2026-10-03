# Path: enigma_lab/search.py
"""Finite reference search over starting positions with all other settings known.

Every candidate transforms the entire ciphertext before checking the aligned
plaintext fragment. This deliberately simple implementation is the correctness
baseline; it performs no early rejection or first-match stopping.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import product
from string import ascii_uppercase

from .engine import Machine, MachineKey, normalize_text

POSITION_COUNT = 26**3


@dataclass(frozen=True)
class SearchSettings:
    """Known settings; starting positions are deliberately absent."""

    rotors: tuple[str, ...]
    reflector: str
    rings: str
    plugboard: tuple[str, ...]


@dataclass(frozen=True)
class SearchResult:
    """An exhaustive result for the specified candidate domain.

    ``complete`` refers to the whole supplied domain, which may be a test subset.
    ``global_domain`` distinguishes coverage of all 17,576 starting positions.
    For a subset, ``searched_positions`` records its exact normalized members;
    for the global domain it is None because the A-Z triple domain is implicit.
    No partial result is returned if execution is interrupted.
    """

    matches: tuple[str, ...]
    candidates_checked: int
    characters_transformed: int
    complete: bool
    domain_size: int
    global_domain: bool
    domain_description: str
    searched_positions: tuple[str, ...] | None
    ciphertext: str
    crib: str
    offset: int
    settings: SearchSettings


def validate_candidate_positions(positions: Iterable[str] | None) -> tuple[str, ...]:
    """Return a finite, nonempty domain of distinct normalized position triples.

    None selects all A-Z triples in lexicographic order. An explicit iterable is
    consumed and validated before any cipher work; duplicates are rejected after
    case normalization. A bare string is not a collection of position triples.
    """
    if positions is None:
        return tuple("".join(letters) for letters in product(ascii_uppercase, repeat=3))
    if isinstance(positions, (str, bytes)):
        raise ValueError("positions must be an iterable of three-letter strings, not a string")
    try:
        iterator = iter(positions)
    except TypeError as exc:
        raise ValueError("positions must be an iterable of three-letter strings") from exc

    normalized_positions = []
    seen = set()
    for value in iterator:
        if len(normalized_positions) == POSITION_COUNT:
            raise ValueError("a candidate domain cannot contain more than 17,576 unique positions")
        if not isinstance(value, str):
            raise ValueError("each candidate position must be a three-letter string")
        position = normalize_text(value, allow_empty=False)
        if len(position) != 3:
            raise ValueError("each candidate position must contain exactly three ASCII letters")
        if position in seen:
            raise ValueError(f"duplicate candidate position: {position}")
        seen.add(position)
        normalized_positions.append(position)
    if not normalized_positions:
        raise ValueError("the candidate domain must not be empty")
    return tuple(normalized_positions)


def search_positions(
    key: MachineKey,
    ciphertext: str,
    crib: str,
    offset: int = 0,
    positions: Iterable[str] | None = None,
) -> SearchResult:
    """Find every start position matching a known plaintext fragment.

    Rotor order, reflector, rings and plugboard are fixed by ``key``. Its
    ``positions`` value is ignored: every candidate supplies its own fresh initial
    positions. The cipher text and crib accept ASCII letters only, with case
    normalization; whitespace stripping belongs to the CLI boundary. ``offset`` is
    a zero-based position in those normalized letters.

    The implementation decrypts the full ciphertext for every candidate, including
    when an early character already disagrees with the crib. Operation counters are
    exact accounting, not measurements of elapsed time or speed.
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
        plaintext = machine.process(ciphertext)
        candidates_checked += 1
        characters_transformed += len(ciphertext)
        if plaintext[offset : offset + len(crib)] == crib:
            matches.append(start)

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

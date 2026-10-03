# Path: working/enigma_lab/specs.py
"""Fixed Enigma I / I-V subset specifications, in A-Z contact order.

Data reference: https://www.cryptomuseum.com/crypto/enigma/wiring.htm
Notches below are *visible pre-step window letters*, not physical notch labels.
Inverse maps are derived from each forward permutation rather than hand-copied.
"""

from dataclasses import dataclass
from types import MappingProxyType

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _permutation(wiring: str) -> tuple[int, ...]:
    if len(wiring) != 26 or set(wiring) != set(ALPHABET):
        raise ValueError("Wiring must be a permutation of A-Z.")
    return tuple(ALPHABET.index(letter) for letter in wiring)


@dataclass(frozen=True)
class RotorSpec:
    name: str
    wiring: tuple[int, ...]
    inverse: tuple[int, ...]
    notch: int


def _rotor(name: str, wiring: str, notch: str) -> RotorSpec:
    forward = _permutation(wiring)
    backward = [0] * 26
    for source, destination in enumerate(forward):
        backward[destination] = source
    return RotorSpec(name, forward, tuple(backward), ALPHABET.index(notch))


ROTORS = MappingProxyType(
    {
        "I": _rotor("I", "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
        "II": _rotor("II", "AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
        "III": _rotor("III", "BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
        "IV": _rotor("IV", "ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
        "V": _rotor("V", "VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
    }
)
REFLECTORS = MappingProxyType(
    {
        "B": _permutation("YRUHQSLDPXNGOKMIEBFZCWVJAT"),
        "C": _permutation("FVPJIAOYEDRZXWGCTKUQSBNMHL"),
    }
)

for _mapping in REFLECTORS.values():
    if any(_mapping[_mapping[i]] != i or _mapping[i] == i for i in range(26)):
        raise ValueError("Reflectors must pair different contacts reciprocally.")

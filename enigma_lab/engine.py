# Path: working/enigma_lab/engine.py
"""Three-rotor Enigma with explicit key and running state.

Public rotor order, positions, ring settings and step flags are left to right.
Positions describe windows *before* the next keypress; each key steps first.
Only ASCII letters are accepted. Normalization validates a whole message before
changing state, so a rejected message cannot partly consume the rotor sequence.
"""

from dataclasses import dataclass
from string import ascii_letters, whitespace

from .specs import ALPHABET, REFLECTORS, ROTORS, RotorSpec


def normalize_text(text: str, *, strip_whitespace: bool = False, allow_empty: bool = True) -> str:
    """Uppercase ASCII letters, optionally dropping only ASCII whitespace.

    Check before uppercasing: Unicode characters such as sharp-s must not
    silently turn into different, apparently valid letters or change length.
    """
    if not isinstance(text, str):
        raise ValueError("Text must be a string.")
    normalized = []
    for index, char in enumerate(text):
        if char in ascii_letters:
            normalized.append(char.upper())
        elif strip_whitespace and char in whitespace:
            continue
        else:
            raise ValueError(f"Expected an ASCII letter at index {index}; got {char!r}.")
    if not normalized and not allow_empty:
        raise ValueError("Text must contain at least one ASCII letter.")
    return "".join(normalized)


def _three_letters(value: str, label: str) -> str:
    result = normalize_text(value)
    if len(result) != 3:
        raise ValueError(f"{label} must contain exactly three ASCII letters.")
    return result


def _plug_pairs(pairs: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if not isinstance(pairs, (tuple, list)):
        raise ValueError("Plugboard must be a tuple or list of letter pairs.")
    if len(pairs) > 13:
        raise ValueError("A plugboard has at most 13 disjoint pairs.")
    used = set()
    canonical = []
    for pair in pairs:
        normalized = normalize_text(pair)
        if len(normalized) != 2 or normalized[0] == normalized[1]:
            raise ValueError("Each plug pair must contain two different ASCII letters.")
        if used.intersection(normalized):
            raise ValueError("A letter may occur in only one plug pair.")
        used.update(normalized)
        canonical.append("".join(sorted(normalized)))
    return tuple(sorted(canonical))


def parse_plugboard(text: str) -> tuple[str, ...]:
    """Parse pairs separated by ASCII whitespace, for example 'AV BS CG'."""
    if not isinstance(text, str) or not text.isascii():
        raise ValueError("Plugboard text must be ASCII.")
    return _plug_pairs(text.split())


@dataclass(frozen=True)
class MachineKey:
    """Validated, immutable initial settings; running positions live in Machine.

    Rings and positions use letters A-Z. A is internal index zero. Rotor names
    are I-V, the reflector is wide B/C, and plug pairs are disjoint. Thirteen
    pairs are physically possible; historical operating rules often used ten.
    """

    rotors: tuple[str, str, str] = ("I", "II", "III")
    reflector: str = "B"
    rings: str = "AAA"
    positions: str = "AAA"
    plugboard: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.rotors, (tuple, list)) or len(self.rotors) != 3:
            raise ValueError("Choose exactly three distinct rotors from I-V.")
        if any(not isinstance(name, str) or name not in ROTORS for name in self.rotors):
            raise ValueError("Rotor names must be I, II, III, IV or V.")
        if len(set(self.rotors)) != 3:
            raise ValueError("A rotor cannot occupy two slots.")
        if not isinstance(self.reflector, str) or self.reflector not in REFLECTORS:
            raise ValueError("Reflector must be wide B or C.")
        object.__setattr__(self, "rotors", tuple(self.rotors))
        object.__setattr__(self, "rings", _three_letters(self.rings, "Ring settings"))
        object.__setattr__(self, "positions", _three_letters(self.positions, "Positions"))
        object.__setattr__(self, "plugboard", _plug_pairs(self.plugboard))


def _rotor_signal(spec: RotorSpec, signal: int, position: int, ring: int, reverse: bool) -> int:
    offset = position - ring
    contacts = spec.inverse if reverse else spec.wiring
    # Shift into the rotor's coordinate frame, wire through, then shift out.
    return (contacts[(signal + offset) % 26] - offset) % 26


def rotor_signal(
    spec: RotorSpec, signal: int, position: int, ring: int, reverse: bool = False
) -> int:
    """Validated single-rotor operation for diagnostics and teaching."""
    if not isinstance(spec, RotorSpec) or spec not in ROTORS.values():
        raise ValueError("Use a supported rotor specification from ROTORS.")
    if any(type(value) is not int or not 0 <= value < 26 for value in (signal, position, ring)):
        raise ValueError("Signal, position and ring must be integer indices 0..25.")
    if type(reverse) is not bool:
        raise ValueError("reverse must be a boolean.")
    return _rotor_signal(spec, signal, position, ring, reverse)


@dataclass(frozen=True)
class SignalStage:
    component: str
    direction: str
    input_letter: str
    output_letter: str


@dataclass(frozen=True)
class LetterTrace:
    input_letter: str
    output_letter: str
    before: str
    after: str
    steps: tuple[bool, bool, bool]
    path: tuple[SignalStage, ...]


class Machine:
    """Mutable message state, with an immutable initial key.

    process() continues from current positions; reset() restores the original key
    positions. reset('XYZ') sets a one-off state without changing the initial key.
    Instances are not thread-safe; search resets positions for every candidate.
    """

    def __init__(self, key: MachineKey):
        if not isinstance(key, MachineKey):
            raise ValueError("Machine requires a validated MachineKey.")
        self._key = key
        self._rotors = tuple(ROTORS[name] for name in key.rotors)
        self._rings = tuple(ALPHABET.index(letter) for letter in key.rings)
        self._reflector = REFLECTORS[key.reflector]
        plugs = list(range(26))
        for pair in key.plugboard:
            first, second = (ALPHABET.index(letter) for letter in pair)
            plugs[first], plugs[second] = second, first
        self._plugs = tuple(plugs)
        self.reset()

    @property
    def key(self) -> MachineKey:
        return self._key

    @property
    def positions(self) -> str:
        return "".join(ALPHABET[index] for index in self._positions)

    def reset(self, positions: str | None = None) -> None:
        text = self.key.positions if positions is None else _three_letters(positions, "Positions")
        self._positions = tuple(ALPHABET.index(letter) for letter in text)

    def _step(self) -> tuple[bool, bool, bool]:
        # Both decisions use the SAME pre-key window state. The notch belongs
        # to the letter ring, so these window tests do not subtract ring settings.
        middle_notch = self._positions[1] == self._rotors[1].notch
        right_notch = self._positions[2] == self._rotors[2].notch
        movement = (middle_notch, middle_notch or right_notch, True)
        self._positions = tuple(
            (position + int(move)) % 26
            for position, move in zip(self._positions, movement, strict=False)
        )
        return movement

    def _signal(self, letter: str, record: bool) -> tuple[str, tuple[SignalStage, ...]]:
        signal = ALPHABET.index(letter)
        path = []
        previous = signal
        signal = self._plugs[signal]
        if record:
            path.append(SignalStage("plugboard", "in", ALPHABET[previous], ALPHABET[signal]))
        for index in (2, 1, 0):
            previous = signal
            signal = _rotor_signal(
                self._rotors[index], signal, self._positions[index], self._rings[index], False
            )
            if record:
                path.append(
                    SignalStage(
                        self._rotors[index].name, "forward", ALPHABET[previous], ALPHABET[signal]
                    )
                )
        previous = signal
        signal = self._reflector[signal]
        if record:
            path.append(
                SignalStage(self.key.reflector, "reflect", ALPHABET[previous], ALPHABET[signal])
            )
        for index in (0, 1, 2):
            previous = signal
            signal = _rotor_signal(
                self._rotors[index], signal, self._positions[index], self._rings[index], True
            )
            if record:
                path.append(
                    SignalStage(
                        self._rotors[index].name, "reverse", ALPHABET[previous], ALPHABET[signal]
                    )
                )
        previous = signal
        signal = self._plugs[signal]
        if record:
            path.append(SignalStage("plugboard", "out", ALPHABET[previous], ALPHABET[signal]))
        return ALPHABET[signal], tuple(path)

    def key_press(self, letter: str) -> str:
        text = normalize_text(letter)
        if len(text) != 1:
            raise ValueError("key_press requires exactly one ASCII letter.")
        self._step()
        return self._signal(text, False)[0]

    def trace_letter(self, letter: str) -> LetterTrace:
        text = normalize_text(letter)
        if len(text) != 1:
            raise ValueError("trace_letter requires exactly one ASCII letter.")
        before = self.positions
        steps = self._step()
        output, path = self._signal(text, True)
        return LetterTrace(text, output, before, self.positions, steps, path)

    def process(self, text: str) -> str:
        normalized = normalize_text(text)  # Validate fully before advancing.
        output = []
        for letter in normalized:
            self._step()
            output.append(self._signal(letter, False)[0])
        return "".join(output)

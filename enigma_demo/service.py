# Path: enigma_demo/service.py
"""Validate browser requests before calling the unchanged cipher engine."""

from dataclasses import asdict, dataclass

from enigma_lab.engine import Machine, MachineKey, normalize_text, parse_plugboard

MAX_TEXT_LETTERS = 256
MAX_BODY_BYTES = 32768


def _object(value, allowed, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object.")
    if not set(value).issubset(allowed):
        raise ValueError(f"Unexpected field in {label.lower()}.")
    return value


def _key(settings) -> MachineKey:
    settings = _object(
        settings, {"rotors", "reflector", "rings", "positions", "plugboard"}, "Settings"
    )
    return MachineKey(
        rotors=settings.get("rotors", ("I", "II", "III")),
        reflector=settings.get("reflector", "B"),
        rings=settings.get("rings", "AAA"),
        positions=settings.get("positions", "AAA"),
        plugboard=parse_plugboard(settings.get("plugboard", "")),
    )


def _text(value, *, allow_empty):
    text = normalize_text(value, strip_whitespace=True, allow_empty=allow_empty)
    if len(text) > MAX_TEXT_LETTERS:
        raise ValueError(f"Use at most {MAX_TEXT_LETTERS} letters per text field.")
    return text


def transform_payload(payload) -> dict:
    """Return the same normalized settings and trace shape as the trace CLI."""
    payload = _object(payload, {"settings", "text"}, "Transform request")
    key = _key(payload.get("settings", {}))
    text = _text(payload.get("text"), allow_empty=True)
    machine = Machine(key)
    traces = [machine.trace_letter(letter) for letter in text]
    return {
        "settings": asdict(key),
        "input": text,
        "output": "".join(trace.output_letter for trace in traces),
        "final_positions": machine.positions,
        "trace": [asdict(trace) for trace in traces],
    }


@dataclass(frozen=True)
class SearchRequest:
    key: MachineKey
    ciphertext: str
    crib: str
    offset: int
    strategy: str


def prepare_search(payload) -> SearchRequest:
    payload = _object(
        payload, {"settings", "ciphertext", "crib", "offset", "strategy"}, "Search request"
    )
    key = _key(payload.get("settings", {}))
    ciphertext = _text(payload.get("ciphertext"), allow_empty=False)
    crib = _text(payload.get("crib"), allow_empty=False)
    offset = payload.get("offset", 0)
    if type(offset) is not int or offset < 0:
        raise ValueError("Offset must be a nonnegative integer in normalized letters.")
    if offset + len(crib) > len(ciphertext):
        raise ValueError("The crib must fit within the ciphertext at the supplied offset.")
    strategy = payload.get("strategy", "baseline")
    if strategy not in ("baseline", "early"):
        raise ValueError("Strategy must be baseline or early.")
    return SearchRequest(key, ciphertext, crib, offset, strategy)

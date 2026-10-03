# Path: enigma_lab/cli.py
"""Command-line boundary for letter transforms and complete position searches.

ASCII whitespace is removed from message/crib text here; all other nonletters
are rejected. API users receive the stricter engine contract without stripping.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict

from .engine import Machine, MachineKey, normalize_text, parse_plugboard
from .search import search_positions


def _add_settings(parser: argparse.ArgumentParser, *, positions: bool) -> None:
    parser.add_argument(
        "--rotors",
        nargs=3,
        default=("I", "II", "III"),
        metavar=("LEFT", "MIDDLE", "RIGHT"),
        help="three distinct rotors from I-V, ordered left (slow) to right (fast)",
    )
    parser.add_argument("--reflector", default="B", help="wide reflector B or C (default: B)")
    parser.add_argument(
        "--rings", default="AAA", help="three ring letters, left to right (default: AAA)"
    )
    parser.add_argument(
        "--plugboard",
        default="",
        metavar='"AB CD"',
        help='space-separated, disjoint letter pairs, for example "AB CD" (default: none)',
    )
    if positions:
        parser.add_argument(
            "--positions",
            default="AAA",
            help="three window letters before the first keypress (default: AAA)",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m enigma_lab",
        description="Three-rotor Enigma I-V simulator and bounded initial-position search.",
        epilog=(
            "Text accepts ASCII letters, case-insensitively; ASCII whitespace is removed. "
            "Other characters are rejected. This is an educational historical-cipher tool."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    transform = commands.add_parser(
        "transform",
        help="encrypt or decrypt using a known complete machine key",
        description="Transform a message; ASCII whitespace is removed before processing.",
    )
    _add_settings(transform, positions=True)
    transform.add_argument(
        "--text", required=True, help="message to transform (quote text containing spaces)"
    )
    transform.add_argument(
        "--trace",
        action="store_true",
        help="emit JSON with every character's state and signal path",
    )

    search = commands.add_parser(
        "search",
        help="search all 17,576 initial positions with every other setting known",
        description=(
            "Decrypt the full ciphertext under every initial position and return all aligned crib matches. "
            "ASCII whitespace is removed from ciphertext and crib before interpreting the offset."
        ),
    )
    _add_settings(search, positions=False)
    search.add_argument(
        "--ciphertext",
        required=True,
        help="ciphertext, containing ASCII letters and optional ASCII whitespace",
    )
    search.add_argument(
        "--crib",
        required=True,
        help="known plaintext fragment; normalized in the same way as ciphertext",
    )
    search.add_argument(
        "--offset",
        type=int,
        default=0,
        help="zero-based crib offset in normalized letters (default: 0)",
    )
    return parser


def _make_key(args: argparse.Namespace) -> MachineKey:
    return MachineKey(
        rotors=tuple(args.rotors),
        reflector=args.reflector,
        rings=args.rings,
        positions=getattr(args, "positions", "AAA"),
        plugboard=parse_plugboard(args.plugboard),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Return 0 on success, 2 for invalid usage, or 130 on interruption.

    A valid search with no matches is successful and returns zero. argparse raises
    SystemExit(2) for malformed CLI syntax and for validation failures reported with
    parser.error. No partial search result is presented as complete after Ctrl+C.
    """
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        key = _make_key(args)
        if args.command == "transform":
            text = normalize_text(args.text, strip_whitespace=True)
            machine = Machine(key)
            if args.trace:
                traces = [machine.trace_letter(letter) for letter in text]
                print(
                    json.dumps(
                        {
                            "settings": asdict(key),
                            "input": text,
                            "output": "".join(trace.output_letter for trace in traces),
                            "final_positions": machine.positions,
                            "trace": [asdict(trace) for trace in traces],
                        },
                        indent=2,
                    )
                )
            else:
                print(machine.process(text))
        else:
            ciphertext = normalize_text(args.ciphertext, strip_whitespace=True, allow_empty=False)
            crib = normalize_text(args.crib, strip_whitespace=True, allow_empty=False)
            result = search_positions(key, ciphertext, crib, args.offset)
            print(json.dumps(asdict(result), indent=2))
        return 0
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("Interrupted; the command did not complete.", file=sys.stderr)
        return 130
    return 2  # parser.error raises SystemExit; retained for the explicit return contract.

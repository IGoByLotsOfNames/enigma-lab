# Path: tests/test_reference.py
"""Offline comparisons with published vectors and a pinned external oracle.

Expected ciphertext and post-key windows are stored evidence, never generated
by this application at test time. These are software/historical-rule fixtures,
not physical-machine observations or a claim of full Enigma-variant coverage.
"""

import json
import unittest
from pathlib import Path

from enigma_lab.engine import Machine, MachineKey, parse_plugboard

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_key(settings):
    plugs = settings.get("plugboard", ())
    if isinstance(plugs, str):
        plugs = parse_plugboard(plugs)
    return MachineKey(
        rotors=tuple(settings["rotors"]),
        reflector=settings.get("reflector", "B"),
        rings=settings.get("rings", "AAA"),
        positions=settings.get("windows", settings.get("positions", "AAA")),
        plugboard=tuple(plugs),
    )


class PublishedReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((FIXTURES / "published_cases.json").read_text(encoding="utf-8"))

    def test_published_whole_message_vectors_in_both_directions(self):
        cases = [
            case for case in self.registry["fixtures"] if "input" in case and "expected" in case
        ]
        self.assertTrue(cases, "Published message fixtures must not silently disappear")
        for case in cases:
            with self.subTest(fixture=case["id"]):
                key = fixture_key(case["settings"])
                self.assertEqual(Machine(key).process(case["input"]), case["expected"])
                self.assertEqual(Machine(key).process(case["expected"]), case["input"])

    def test_published_and_derived_step_traces_match_their_declared_order(self):
        # The registry labels the KDO trace as published and the ADU trace as derived.
        cases = [
            case for case in self.registry["fixtures"] if "expected_windows_after_keys" in case
        ]
        self.assertTrue(cases, "Mechanical trace fixtures must not silently disappear")
        for case in cases:
            for rings in ("AAA", "BUL"):
                with self.subTest(fixture=case["id"], rings=rings):
                    machine = Machine(
                        MachineKey(
                            rotors=tuple(case["rotors"]),
                            rings=rings,
                            positions=case["initial_windows"],
                        )
                    )
                    observed = []
                    for _ in case["expected_windows_after_keys"]:
                        machine.key_press("A")
                        observed.append(machine.positions)
                    self.assertEqual(observed, case["expected_windows_after_keys"])
        # Non-A ring repeats are derived checks of fixed visible-window notches.


class IndependentOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oracle = json.loads((FIXTURES / "oracle_fixtures.json").read_text(encoding="utf-8"))

    def test_fixture_collection_covers_both_reflectors_and_diverse_settings(self):
        cases = self.oracle["fixtures"]
        self.assertTrue(cases, "The independent oracle corpus must not be empty")
        self.assertEqual({case["settings"]["reflector"] for case in cases}, {"B", "C"})
        self.assertTrue(any(case["settings"]["rings"] != "AAA" for case in cases))
        self.assertTrue(any(case["settings"]["plugboard"] for case in cases))
        self.assertTrue(any("IV" in case["settings"]["rotors"] for case in cases))
        self.assertTrue(any("V" in case["settings"]["rotors"] for case in cases))

    def test_every_oracle_ciphertext_matches_with_fresh_machine_state(self):
        for case in self.oracle["fixtures"]:
            with self.subTest(fixture=case["id"]):
                machine = Machine(fixture_key(case["settings"]))
                self.assertEqual(machine.process(case["input"]), case["expected"])
                self.assertEqual(machine.positions, case["expected_final_windows"])

    def test_every_oracle_ciphertext_decrypts_to_its_stored_plaintext(self):
        for case in self.oracle["fixtures"]:
            with self.subTest(fixture=case["id"]):
                machine = Machine(fixture_key(case["settings"]))
                self.assertEqual(machine.process(case["expected"]), case["input"])
                self.assertEqual(machine.positions, case["expected_final_windows"])

    def test_each_key_trace_matches_independent_character_and_window_receipts(self):
        for case in self.oracle["fixtures"]:
            with self.subTest(fixture=case["id"]):
                machine = Machine(fixture_key(case["settings"]))
                traces = [machine.trace_letter(letter) for letter in case["input"]]
                self.assertEqual("".join(trace.output_letter for trace in traces), case["expected"])
                self.assertEqual(
                    [trace.after for trace in traces], case["expected_windows_after_keys"]
                )
                self.assertEqual(machine.positions, case["expected_final_windows"])


if __name__ == "__main__":
    unittest.main()

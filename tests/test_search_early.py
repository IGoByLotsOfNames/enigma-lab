# Path: tests/test_search_early.py
"""Search equivalence and exact work accounting, without timing assertions."""

import json
import unittest
from dataclasses import replace
from itertools import chain, product
from pathlib import Path
from string import ascii_uppercase
from unittest.mock import patch

from enigma_lab.engine import Machine, MachineKey
from enigma_lab.search import search_positions
from enigma_lab.search_early import search_positions_early


class EarlySearchTests(unittest.TestCase):
    def assert_same_semantics(self, baseline, early):
        self.assertEqual(
            baseline,
            replace(early, characters_transformed=baseline.characters_transformed),
        )
        self.assertLessEqual(early.characters_transformed, baseline.characters_transformed)

    def test_full_domain_matches_pinned_oracle_and_baseline_semantics(self):
        path = Path(__file__).parent / "fixtures" / "oracle_fixtures.json"
        oracle = json.loads(path.read_text(encoding="utf-8"))
        fixture = oracle["search_fixtures"][0]
        self.assertEqual(oracle["oracle"]["name"], "py-enigma")
        self.assertEqual(oracle["oracle"]["version"], "1.0.2")
        key = MachineKey(
            rotors=tuple(fixture["rotors"]),
            reflector=fixture["reflector"],
            rings=fixture["rings"],
            plugboard=tuple(fixture["plugboard"]),
            positions="XYZ",
        )
        baseline = search_positions(key, fixture["ciphertext"], fixture["crib"], fixture["offset"])
        early = search_positions_early(
            key, fixture["ciphertext"], fixture["crib"], fixture["offset"]
        )
        self.assert_same_semantics(baseline, early)
        self.assertEqual(early.matches, tuple(fixture["matching_initial_windows"]))
        self.assertEqual(early.candidates_checked, fixture["candidates_checked"])
        self.assertTrue(early.complete)
        self.assertTrue(early.global_domain)
        self.assertIsNone(early.searched_positions)
        self.assertLess(early.characters_transformed, fixture["characters_transformed"])

    def test_exact_character_counts_include_prefix_and_first_mismatch(self):
        # Published default key decrypts BDZGO to AAAAA. The last column is
        # hand-counted keypresses, not a timing expectation or benchmark result.
        cases = (
            ("A", 0, ("AAA",), 1),
            ("AA", 0, ("AAA",), 2),
            ("B", 0, (), 1),
            ("AB", 0, (), 2),
            ("B", 2, (), 3),
            ("AA", 2, ("AAA",), 4),
            ("AA", 3, ("AAA",), 5),
        )
        for crib, offset, matches, count in cases:
            with self.subTest(crib=crib, offset=offset):
                baseline = search_positions(MachineKey(), "BDZGO", crib, offset, ("AAA",))
                early = search_positions_early(MachineKey(), "BDZGO", crib, offset, ("AAA",))
                self.assert_same_semantics(baseline, early)
                self.assertEqual(early.matches, matches)
                self.assertEqual(early.characters_transformed, count)

    def test_successful_candidate_does_not_transform_irrelevant_suffix(self):
        baseline = search_positions(MachineKey(), "BDZGO", "A", positions=("AAA",))
        early = search_positions_early(MachineKey(), "BDZGO", "A", positions=("AAA",))
        self.assert_same_semantics(baseline, early)
        self.assertEqual(early.characters_transformed, 1)
        self.assertEqual(baseline.characters_transformed, 5)

    def test_last_character_crib_can_have_no_work_reduction(self):
        domain = ("AAA", "AAB", "XYZ")
        baseline = search_positions(MachineKey(), "BDZGO", "A", 4, domain)
        early = search_positions_early(MachineKey(), "BDZGO", "A", 4, domain)
        self.assert_same_semantics(baseline, early)
        self.assertEqual(early.characters_transformed, 15)
        self.assertEqual(early.characters_transformed, baseline.characters_transformed)

    def test_no_match_still_visits_every_candidate(self):
        domain = ("XYZ", "AAA", "ZZZ")
        baseline = search_positions(MachineKey(), "AAAAA", "A", positions=domain)
        early = search_positions_early(MachineKey(), "AAAAA", "A", positions=domain)
        self.assert_same_semantics(baseline, early)
        self.assertEqual(early.matches, ())  # A cannot encipher to A at any position.
        self.assertEqual(early.candidates_checked, len(domain))
        self.assertEqual(early.characters_transformed, len(domain))

    def test_ambiguous_matches_preserve_supplied_order_and_do_not_stop_early(self):
        buckets = {}
        for letter in ascii_uppercase:
            position = "AA" + letter
            plaintext = Machine(MachineKey(positions=position)).process("A")
            buckets.setdefault(plaintext, []).append(position)
        crib, positions = next(
            (text, starts) for text, starts in sorted(buckets.items()) if len(starts) > 1
        )
        domain = tuple(reversed(positions)) + ("ZZZ",)
        baseline = search_positions(MachineKey(), "AAAAA", crib, positions=domain)
        early = search_positions_early(MachineKey(), "AAAAA", crib, positions=domain)
        self.assert_same_semantics(baseline, early)
        self.assertGreater(len(early.matches), 1)
        self.assertEqual(early.matches[: len(positions)], tuple(reversed(positions)))
        self.assertEqual(early.candidates_checked, len(domain))
        self.assertEqual(early.characters_transformed, len(domain))

    def test_every_candidate_resets_after_a_previous_full_crib_match(self):
        domain = ("AAA", "XYZ", "ZZZ", "AAB")
        baseline = search_positions(MachineKey(), "BDZGO", "AAAAA", positions=domain)
        early = search_positions_early(MachineKey(), "BDZGO", "AAAAA", positions=domain)
        self.assert_same_semantics(baseline, early)
        self.assertEqual(early.matches, ("AAA",))
        self.assertEqual(early.candidates_checked, 4)

    def test_offset_prefix_preserves_nondefault_notch_and_plugboard_behavior(self):
        path = Path(__file__).parent / "fixtures" / "oracle_fixtures.json"
        oracle = json.loads(path.read_text(encoding="utf-8"))
        ids = {
            "nondefault-ring-double-step-C",
            "oracle-IV-V-wrap-C",
            "published-nondefault-message",
        }
        cases = [case for case in oracle["fixtures"] if case["id"] in ids]
        self.assertEqual(len(cases), len(ids))
        for fixture in cases:
            settings = fixture["settings"]
            key = MachineKey(
                rotors=tuple(settings["rotors"]),
                reflector=settings["reflector"],
                rings=settings["rings"],
                positions="ZZZ",
                plugboard=tuple(settings["plugboard"]),
            )
            true_start = settings["windows"]
            domain = tuple(dict.fromkeys(("AAA", true_start, "ZZZ", "QWE")))
            for offset in (2, len(fixture["input"]) - 2):
                with self.subTest(fixture=fixture["id"], offset=offset):
                    crib = fixture["input"][offset : offset + 2]
                    baseline = search_positions(key, fixture["expected"], crib, offset, domain)
                    early = search_positions_early(key, fixture["expected"], crib, offset, domain)
                    self.assert_same_semantics(baseline, early)
                    self.assertIn(true_start, early.matches)

    def test_key_positions_are_ignored_without_mutating_key_or_another_machine(self):
        key = MachineKey(positions="ADU", rings="BUL")
        other_machine = Machine(key)
        other_machine.process("ABC")
        before = other_machine.positions
        domain = ("AAA", "ADU", "XYZ")
        first = search_positions_early(key, "BDZGO", "A", positions=domain)
        alternate = search_positions_early(
            replace(key, positions="ZZZ"), "BDZGO", "A", positions=domain
        )
        self.assertEqual(first, alternate)
        self.assertEqual(key.positions, "ADU")
        self.assertEqual(other_machine.positions, before)

    def test_case_and_single_use_domain_generator_are_normalized(self):
        seen = []

        def domain():
            for position in ("xyz", "aaa", "aab"):
                seen.append(position)
                yield position

        result = search_positions_early(MachineKey(), "bdzgo", "aaaaa", positions=domain())
        baseline = search_positions(MachineKey(), "BDZGO", "AAAAA", positions=("XYZ", "AAA", "AAB"))
        self.assert_same_semantics(baseline, result)
        self.assertEqual(seen, ["xyz", "aaa", "aab"])
        self.assertEqual(result.searched_positions, ("XYZ", "AAA", "AAB"))

    def test_explicit_complete_domain_is_global_even_in_reverse_order(self):
        domain = ("".join(letters) for letters in product(reversed(ascii_uppercase), repeat=3))
        result = search_positions_early(MachineKey(), "A", "A", positions=domain)
        self.assertTrue(result.complete)
        self.assertTrue(result.global_domain)
        self.assertEqual(result.matches, ())
        self.assertEqual(result.domain_size, 17576)
        self.assertEqual(result.candidates_checked, 17576)
        self.assertEqual(result.characters_transformed, 17576)
        self.assertIsNone(result.searched_positions)

    def test_invalid_key_offset_or_full_text_matches_baseline_rejection(self):
        cases = [
            (None, "B", "A", 0),
            ("AAA", "B", "A", 0),
            (MachineKey(), "B", "A", -1),
            (MachineKey(), "B", "A", True),
            (MachineKey(), "B", "A", 0.0),
            (MachineKey(), "B", "A", "0"),
            (MachineKey(), "B", "A", 1),
            (MachineKey(), "B", "AA", 0),
            (MachineKey(), "", "A", 0),
            (MachineKey(), "B", "", 0),
            (MachineKey(), "BDZGO!", "A", 0),
            (MachineKey(), "BDZGO ", "A", 0),
            (MachineKey(), "B", "ß", 0),
            (MachineKey(), "B", "ſ", 0),
            (MachineKey(), None, "A", 0),
            (MachineKey(), "B", None, 0),
        ]
        for key, ciphertext, crib, offset in cases:
            with self.subTest(key=key, ciphertext=ciphertext, crib=crib, offset=offset):
                errors = []
                for implementation in (search_positions, search_positions_early):
                    with self.assertRaises(ValueError) as context:
                        implementation(key, ciphertext, crib, offset, ("AAA",))
                    errors.append(str(context.exception))
                self.assertEqual(errors[0], errors[1])

    def test_invalid_candidate_domains_match_baseline_rejection(self):
        domains = (
            [],
            (),
            "AAA",
            b"AAA",
            True,
            ["AAA", "aaa"],
            ["AA"],
            ["AAAA"],
            ["A A"],
            ["AA1"],
            ["AAſ"],
            [None],
        )
        for domain in domains:
            with self.subTest(domain=domain):
                errors = []
                for implementation in (search_positions, search_positions_early):
                    with self.assertRaises(ValueError) as context:
                        implementation(MachineKey(), "B", "A", positions=domain)
                    errors.append(str(context.exception))
                self.assertEqual(errors[0], errors[1])

    def test_invalid_unused_suffix_is_rejected_before_any_cipher_work(self):
        with patch("enigma_lab.search_early.Machine") as machine:
            with self.assertRaises(ValueError):
                search_positions_early(MachineKey(), "BDZGO!", "A", positions=("AAA",))
            machine.assert_not_called()

    def test_entire_domain_is_validated_before_any_cipher_work(self):
        with patch("enigma_lab.search_early.Machine") as machine:
            with self.assertRaises(ValueError):
                search_positions_early(
                    MachineKey(), "B", "A", positions=chain(("AAA", "AAB"), ("AA!",))
                )
            machine.assert_not_called()

    def test_domain_validation_retains_finite_maximum(self):
        yielded = 0

        def domain():
            nonlocal yielded
            for letters in product(ascii_uppercase, repeat=3):
                yielded += 1
                yield "".join(letters)
            yielded += 1
            yield "AAA"
            self.fail("Domain iterator was consumed past its maximum rejection point")

        with patch("enigma_lab.search_early.Machine") as machine:
            with self.assertRaisesRegex(ValueError, "17,576"):
                search_positions_early(MachineKey(), "B", "A", positions=domain())
            machine.assert_not_called()
        self.assertEqual(yielded, 17577)

    def test_interruption_does_not_return_partial_result(self):
        with patch.object(Machine, "key_press", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                search_positions_early(MachineKey(), "BDZGO", "AAAAA", positions=("AAA", "XYZ"))


if __name__ == "__main__":
    unittest.main()

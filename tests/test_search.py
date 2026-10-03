# Path: tests/test_search.py
"""Finite search contracts and an independently generated complete answer set."""

import json
import unittest
from dataclasses import FrozenInstanceError, replace
from itertools import chain, product
from pathlib import Path
from string import ascii_uppercase
from unittest.mock import patch

from enigma_lab.engine import Machine, MachineKey
from enigma_lab.search import search_positions, validate_candidate_positions


class CandidateDomainTests(unittest.TestCase):
    def test_default_domain_is_every_distinct_triple_in_order(self):
        domain = validate_candidate_positions(None)
        self.assertEqual(len(domain), 26**3)
        self.assertEqual(len(set(domain)), 26**3)
        self.assertEqual(domain[0], "AAA")
        self.assertEqual(domain[-1], "ZZZ")
        self.assertEqual(domain, tuple(sorted(domain)))
        self.assertTrue(
            all(len(value) == 3 and set(value) <= set(ascii_uppercase) for value in domain)
        )

    def test_generator_is_consumed_and_normalized_once(self):
        seen = []

        def domain():
            for value in ("xyz", "aBc", "aaa"):
                seen.append(value)
                yield value

        self.assertEqual(validate_candidate_positions(domain()), ("XYZ", "ABC", "AAA"))
        self.assertEqual(seen, ["xyz", "aBc", "aaa"])

    def test_invalid_domain_types(self):
        for value in ("AAA", b"AAA", 3, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_candidate_positions(value)

    def test_empty_and_malformed_members_are_rejected(self):
        for domain in (
            [],
            (),
            [""],
            ["AA"],
            ["AAAA"],
            ["A A"],
            ["AA1"],
            ["AAſ"],
            ["AAı"],
            ["AAß"],
            [None],
            [1],
            [True],
        ):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                validate_candidate_positions(domain)

    def test_duplicates_are_rejected_after_case_normalization(self):
        for domain in (("AAA", "AAA"), ("abc", "ABC")):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                validate_candidate_positions(domain)

    def test_more_than_maximum_candidates_has_a_finite_rejection(self):
        count = 0

        def domain():
            nonlocal count
            for letters in product(ascii_uppercase, repeat=3):
                count += 1
                yield "".join(letters)
            count += 1
            yield "AAA"
            self.fail("validation consumed the iterator beyond its maximum bound")

        with self.assertRaisesRegex(ValueError, "17,576"):
            validate_candidate_positions(domain())
        self.assertEqual(count, 17577)


class SearchTests(unittest.TestCase):
    def test_complete_supplied_domain_agrees_with_independent_oracle(self):
        """One full five-letter search, against pinned Py-Enigma enumeration."""
        fixture_path = Path(__file__).parent / "fixtures" / "oracle_fixtures.json"
        fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
        fixture = fixtures["search_fixtures"][0]
        self.assertEqual(fixtures["oracle"]["name"], "py-enigma")
        self.assertEqual(fixtures["oracle"]["version"], "1.0.2")
        key = MachineKey(
            rotors=fixture["rotors"],
            reflector=fixture["reflector"],
            rings=fixture["rings"],
            plugboard=fixture["plugboard"],
            positions="XYZ",
        )
        # An explicit complete domain also must be identified as global. Reverse
        # order exercises enumeration independence; there is one oracle match.
        domain = ("".join(letters) for letters in product(reversed(ascii_uppercase), repeat=3))
        result = search_positions(
            key, fixture["ciphertext"], fixture["crib"], fixture["offset"], domain
        )
        self.assertEqual(result.matches, tuple(fixture["matching_initial_windows"]))
        self.assertEqual(result.candidates_checked, fixture["candidates_checked"])
        self.assertEqual(result.characters_transformed, fixture["characters_transformed"])
        self.assertEqual(result.domain_size, 17576)
        self.assertTrue(result.complete)
        self.assertTrue(result.global_domain)
        self.assertIsNone(result.searched_positions)
        self.assertEqual(result.settings.rotors, tuple(fixture["rotors"]))
        self.assertEqual(result.settings.rings, fixture["rings"])
        self.assertEqual(result.settings.reflector, fixture["reflector"])
        self.assertEqual(result.settings.plugboard, tuple(fixture["plugboard"]))

    def test_every_matching_candidate_is_returned_in_supplied_order(self):
        # Two starts with the same first decoded letter are a real ambiguity,
        # not a request to stop at whichever one appears first.
        buckets = {}
        for letter in ascii_uppercase:
            position = "AA" + letter
            plaintext = Machine(MachineKey(positions=position)).process("A")
            buckets.setdefault(plaintext, []).append(position)
        crib, matches = next(
            (text, positions) for text, positions in sorted(buckets.items()) if len(positions) > 1
        )
        domain = tuple(reversed(matches))
        result = search_positions(MachineKey(), "A", crib, positions=domain)
        self.assertEqual(result.matches, domain)
        self.assertGreater(len(result.matches), 1)
        self.assertEqual(result.candidates_checked, len(domain))
        self.assertTrue(result.complete)
        self.assertFalse(result.global_domain)
        self.assertEqual(result.searched_positions, domain)

    def test_no_match_is_a_successful_complete_result(self):
        result = search_positions(MachineKey(), "A", "A", positions=("AAA", "AAB"))
        self.assertEqual(result.matches, ())
        self.assertEqual(result.candidates_checked, 2)
        self.assertEqual(result.characters_transformed, 2)
        self.assertTrue(result.complete)

    def test_search_does_not_stop_after_first_match(self):
        result = search_positions(MachineKey(), "BDZGO", "AAAAA", positions=("AAA", "XYZ", "ZZZ"))
        self.assertEqual(result.matches, ("AAA",))
        self.assertEqual(result.candidates_checked, 3)
        self.assertEqual(result.characters_transformed, 15)
        self.assertEqual(result.searched_positions, ("AAA", "XYZ", "ZZZ"))

    def test_known_key_and_nonzero_crib_offset_are_respected(self):
        key = MachineKey(
            rotors=("V", "III", "II"),
            reflector="C",
            rings="BUL",
            positions="QWE",
            plugboard=("AB", "XY"),
        )
        plaintext = "HELLOWORLD"
        ciphertext = Machine(key).process(plaintext)
        domain = ("AAA", "QWE", "XYZ")
        expected = tuple(
            position
            for position in domain
            if Machine(replace(key, positions=position)).process(ciphertext)[3:6] == "LOW"
        )
        result = search_positions(key, ciphertext, "LOW", 3, domain)
        self.assertEqual(result.matches, expected)
        self.assertIn("QWE", result.matches)
        self.assertEqual(result.offset, 3)
        self.assertEqual(result.settings.reflector, "C")
        self.assertEqual(result.settings.rings, "BUL")
        self.assertEqual(result.settings.plugboard, ("AB", "XY"))

    def test_key_initial_positions_are_ignored_without_mutating_key(self):
        first_key = MachineKey(positions="AAA")
        other_key = replace(first_key, positions="ZZZ")
        first = search_positions(first_key, "BDZGO", "AAAAA", positions=("AAA", "XYZ"))
        other = search_positions(other_key, "BDZGO", "AAAAA", positions=("AAA", "XYZ"))
        self.assertEqual(first, other)
        self.assertEqual(other_key.positions, "ZZZ")

    def test_ascii_case_and_generator_domain_are_normalized(self):
        domain = (position for position in ("aaa", "xyz"))
        result = search_positions(MachineKey(), "bdzgo", "aaaaa", positions=domain)
        self.assertEqual(result.matches, ("AAA",))
        self.assertEqual(result.ciphertext, "BDZGO")
        self.assertEqual(result.crib, "AAAAA")
        self.assertEqual(result.searched_positions, ("AAA", "XYZ"))

    def test_crib_can_end_at_last_character(self):
        result = search_positions(MachineKey(), "BDZGO", "A", 4, positions=("AAA",))
        self.assertEqual(result.matches, ("AAA",))
        self.assertEqual(result.characters_transformed, 5)

    def test_invalid_key_is_rejected(self):
        for key in (None, "AAA", {}, True):
            with self.subTest(key=key), self.assertRaises(ValueError):
                search_positions(key, "B", "A", positions=("AAA",))

    def test_offset_type_sign_and_bounds_are_checked(self):
        for offset in (-1, True, False, 0.0, "0", None, 1):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                search_positions(MachineKey(), "B", "A", offset, positions=("AAA",))

    def test_invalid_messages_or_cribs_are_rejected_in_full(self):
        cases = (
            ("", "A"),
            ("B", ""),
            ("B", "AA"),
            ("BD!", "A"),
            ("B D", "A"),
            ("BD", "A "),
            ("B", "ſ"),
            ("B", "ß"),
            ("B", "ı"),
            (None, "A"),
            ("B", None),
        )
        for ciphertext, crib in cases:
            with self.subTest(ciphertext=ciphertext, crib=crib), self.assertRaises(ValueError):
                search_positions(MachineKey(), ciphertext, crib, positions=("AAA",))

    def test_entire_domain_is_validated_before_cipher_work(self):
        with patch.object(
            Machine, "process", side_effect=AssertionError("unexpected cipher work")
        ) as process:
            with self.assertRaises(ValueError):
                search_positions(MachineKey(), "B", "A", positions=chain(("AAA", "AAB"), ("AA!",)))
            process.assert_not_called()

    def test_entire_input_is_validated_before_cipher_work(self):
        with patch.object(
            Machine, "process", side_effect=AssertionError("unexpected cipher work")
        ) as process:
            with self.assertRaises(ValueError):
                search_positions(MachineKey(), "BDZGO!", "A", positions=("AAA",))
            process.assert_not_called()

    def test_result_and_known_settings_are_immutable(self):
        result = search_positions(MachineKey(), "B", "A", positions=("AAA",))
        with self.assertRaises(FrozenInstanceError):
            result.complete = False
        with self.assertRaises(FrozenInstanceError):
            result.settings.rings = "ZZZ"


if __name__ == "__main__":
    unittest.main()

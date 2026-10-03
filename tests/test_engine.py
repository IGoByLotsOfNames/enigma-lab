# Path: tests/test_engine.py
"""Configuration, state and contact-contract regressions.

These structural checks complement the external vectors in test_reference.py.
Round trips alone are not evidence of historically correct encryption.
"""

import unittest
from dataclasses import FrozenInstanceError, replace
from string import ascii_uppercase

from enigma_lab.engine import (
    Machine,
    MachineKey,
    normalize_text,
    parse_plugboard,
    rotor_signal,
)
from enigma_lab.specs import REFLECTORS, ROTORS, RotorSpec, _permutation


class NormalizationTests(unittest.TestCase):
    def test_ascii_case_is_normalized_without_changing_length(self):
        self.assertEqual(normalize_text("aBcXyZ"), "ABCXYZ")
        self.assertEqual(Machine(MachineKey()).process("aaaaa"), "BDZGO")

    def test_whitespace_requires_explicit_opt_in(self):
        text = " A\tB\nC\rD\vE\fF "
        with self.assertRaises(ValueError):
            normalize_text(text)
        self.assertEqual(normalize_text(text, strip_whitespace=True), "ABCDEF")

    def test_empty_text_policy_is_explicit(self):
        self.assertEqual(normalize_text(""), "")
        self.assertEqual(normalize_text(" \n", strip_whitespace=True), "")
        for text, strip in (("", False), (" \t\n", True)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                normalize_text(text, strip_whitespace=strip, allow_empty=False)

    def test_unicode_letters_and_whitespace_are_not_silently_ascii_folded(self):
        for text in ("é", "ſ", "ı", "ß", "Ａ", "A\u00a0B", "A\u2003B", "🙂"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                normalize_text(text, strip_whitespace=True)

    def test_non_text_and_nonletter_values_are_rejected(self):
        for text in (None, 123, b"ABC", ["A"], "AB!", "AB1", "A\x00B"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                normalize_text(text)


class MachineKeyTests(unittest.TestCase):
    def test_defaults_are_the_documented_three_rotor_key(self):
        self.assertEqual(
            MachineKey(),
            MachineKey(
                rotors=("I", "II", "III"), reflector="B", rings="AAA", positions="AAA", plugboard=()
            ),
        )

    def test_input_collections_are_copied_and_pairs_canonicalized(self):
        rotors = ["V", "III", "II"]
        pairs = ["zy", "ba"]
        key = MachineKey(
            rotors=rotors, reflector="C", rings="bul", positions="qwe", plugboard=pairs
        )
        rotors[0] = "I"
        pairs[0] = "CD"
        self.assertEqual(key.rotors, ("V", "III", "II"))
        self.assertEqual(key.rings, "BUL")
        self.assertEqual(key.positions, "QWE")
        self.assertEqual(key.plugboard, ("AB", "YZ"))
        self.assertIsInstance(key.rotors, tuple)
        self.assertIsInstance(key.plugboard, tuple)

    def test_key_is_frozen_and_hashable(self):
        key = MachineKey()
        with self.assertRaises(FrozenInstanceError):
            key.positions = "XYZ"
        self.assertEqual({key: "known settings"}[MachineKey()], "known settings")

    def test_rotor_selection_requires_three_distinct_supported_names(self):
        for rotors in (
            "III",
            True,
            None,
            ("I", "II"),
            ("I", "II", "III", "IV"),
            ("I", "II", "II"),
            ("I", "II", "VI"),
            ("I", "II", 3),
            ("i", "II", "III"),
        ):
            with self.subTest(rotors=rotors), self.assertRaises(ValueError):
                MachineKey(rotors=rotors)

    def test_only_wide_b_and_c_reflectors_are_supported(self):
        for reflector in ("B", "C"):
            self.assertEqual(MachineKey(reflector=reflector).reflector, reflector)
        for reflector in ("thin-B", "A", "b", None, True, 0):
            with self.subTest(reflector=reflector), self.assertRaises(ValueError):
                MachineKey(reflector=reflector)

    def test_rings_and_windows_require_exactly_three_ascii_letters(self):
        for field in ("rings", "positions"):
            for value in (
                "",
                "AA",
                "AAAA",
                "AA1",
                "A A",
                "AAſ",
                "AAı",
                "AAß",
                (0, 0, 0),
                None,
                True,
            ):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    MachineKey(**{field: value})

    def test_zero_through_thirteen_disjoint_plug_pairs_are_supported(self):
        pairs = tuple(ascii_uppercase[index : index + 2] for index in range(0, 26, 2))
        message = "HELLOWORLD"
        for count in range(14):
            with self.subTest(pair_count=count):
                key = MachineKey(plugboard=pairs[:count])
                self.assertEqual(len(key.plugboard), count)
                ciphertext = Machine(key).process(message)
                self.assertEqual(Machine(key).process(ciphertext), message)
        # This is an API-capacity invariant, not an independent 13-pair oracle.

    def test_malformed_overlapping_or_excessive_plug_pairs_are_rejected(self):
        invalid = (
            "AB CD",
            None,
            True,
            ("AA",),
            ("AB", "AC"),
            ("AB", "BA"),
            ("ab", "Bc"),
            ("ABC",),
            ("A",),
            ("A1",),
            ("Aſ",),
            (None,),
            ("AB",) * 14,
        )
        for pairs in invalid:
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                MachineKey(plugboard=pairs)

    def test_plugboard_text_parser_handles_ascii_whitespace_and_empty_input(self):
        self.assertEqual(parse_plugboard(" va\tSB\n"), ("AV", "BS"))
        self.assertEqual(parse_plugboard(""), ())
        self.assertEqual(parse_plugboard(" \t\n"), ())

    def test_plugboard_parser_rejects_non_ascii_or_invalid_pairs(self):
        for text in (None, 123, b"AB", "AB\u00a0CD", "Aſ", "AB AC", "AA", "ABC"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_plugboard(text)


class SpecificationAndContactTests(unittest.TestCase):
    def test_supported_rotor_tables_have_valid_inverses_and_visible_notches(self):
        expected_notches = {"I": "Q", "II": "E", "III": "V", "IV": "J", "V": "Z"}
        self.assertEqual(set(ROTORS), set(expected_notches))
        for name, spec in ROTORS.items():
            with self.subTest(rotor=name):
                self.assertEqual(spec.name, name)
                self.assertEqual(len(spec.wiring), 26)
                self.assertEqual(set(spec.wiring), set(range(26)))
                self.assertEqual(
                    tuple(spec.inverse[value] for value in spec.wiring), tuple(range(26))
                )
                self.assertEqual(ascii_uppercase[spec.notch], expected_notches[name])

    def test_wide_reflectors_pair_distinct_contacts_reciprocally(self):
        self.assertEqual(set(REFLECTORS), {"B", "C"})
        for name, wiring in REFLECTORS.items():
            with self.subTest(reflector=name):
                self.assertEqual(len(wiring), 26)
                self.assertEqual(set(wiring), set(range(26)))
                self.assertTrue(all(wiring[wiring[index]] == index for index in range(26)))
                self.assertTrue(all(wiring[index] != index for index in range(26)))

    def test_rotor_spec_instances_are_frozen(self):
        local_copy = replace(ROTORS["I"])
        with self.assertRaises(FrozenInstanceError):
            local_copy.notch = 0

    def test_permutation_builder_rejects_incomplete_or_repeated_contacts(self):
        # Exercise the pure validation helper without replacing production tables.
        for wiring in (
            "",
            ascii_uppercase[:-1],
            "A" * 26,
            ascii_uppercase.lower(),
            ascii_uppercase + "A",
        ):
            with self.subTest(wiring=wiring), self.assertRaises(ValueError):
                _permutation(wiring)

    def test_rotated_contact_examples_include_output_shift_and_ring_offset(self):
        # Hand-worked contact-frame examples, independent of the tested function.
        # Rotor III/B with ring A: A enters B, wiring B->D, exit shifts to C.
        examples = (("III", 0, 1, 0, 2), ("I", 0, 1, 0, 9), ("I", 0, 0, 1, 10), ("I", 0, 1, 1, 4))
        for name, signal, position, ring, expected in examples:
            with self.subTest(rotor=name, position=position, ring=ring):
                self.assertEqual(rotor_signal(ROTORS[name], signal, position, ring), expected)
                self.assertEqual(
                    rotor_signal(ROTORS[name], expected, position, ring, reverse=True), signal
                )

    def test_boundary_rotor_frames_retain_inverse_and_relative_offset_properties(self):
        frames = ((0, 0), (1, 0), (25, 0), (0, 1), (25, 25), (4, 20))
        for name, spec in ROTORS.items():
            for position, ring in frames:
                with self.subTest(rotor=name, position=position, ring=ring):
                    for signal in range(26):
                        output = rotor_signal(spec, signal, position, ring)
                        self.assertEqual(
                            rotor_signal(spec, output, position, ring, reverse=True), signal
                        )
                        self.assertEqual(
                            rotor_signal(spec, signal, (position + 7) % 26, (ring + 7) % 26),
                            output,
                        )

    def test_rotor_contact_arguments_are_strict_integer_indices(self):
        for argument in range(3):
            for value in (-1, 26, 1.5, True, False, None, "0"):
                values = [0, 0, 0]
                values[argument] = value
                with self.subTest(argument=argument, value=value), self.assertRaises(ValueError):
                    rotor_signal(ROTORS["I"], *values)

    def test_rotor_contact_requires_supported_spec_and_boolean_direction(self):
        custom = RotorSpec("custom", tuple(range(26)), tuple(range(26)), 0)
        for spec in (None, "I", custom):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                rotor_signal(spec, 0, 0, 0)
        for reverse in (0, 1, None, "reverse"):
            with self.subTest(reverse=reverse), self.assertRaises(ValueError):
                rotor_signal(ROTORS["I"], 0, 0, 0, reverse=reverse)


class MachineStateTests(unittest.TestCase):
    def test_machine_requires_a_validated_key(self):
        for key in (None, "AAA", {}, True):
            with self.subTest(key=key), self.assertRaises(ValueError):
                Machine(key)

    def test_message_chunks_continue_the_same_state(self):
        key = MachineKey(positions="ADU", rings="BUL", reflector="C", plugboard=("AB", "XY"))
        chunked = Machine(key)
        result = chunked.process("HEL") + chunked.process("LOWORLD")
        whole = Machine(key)
        self.assertEqual(result, whole.process("HELLOWORLD"))
        self.assertEqual(chunked.positions, whole.positions)
        self.assertEqual(chunked.key, key)

    def test_empty_message_does_not_advance_state(self):
        machine = Machine(MachineKey(positions="QWE"))
        self.assertEqual(machine.process(""), "")
        self.assertEqual(machine.positions, "QWE")

    def test_reset_replays_initial_settings_after_explicit_override(self):
        key = MachineKey(positions="BLA", rings="BUL")
        machine = Machine(key)
        original = machine.process("HELLO")
        machine.reset("xyz")
        self.assertEqual(machine.positions, "XYZ")
        machine.process("ABC")
        machine.reset()
        self.assertEqual(machine.positions, "BLA")
        self.assertEqual(machine.process("HELLO"), original)
        self.assertEqual(machine.key, key)

    def test_invalid_reset_does_not_mutate_existing_state(self):
        machine = Machine(MachineKey(positions="ADU"))
        machine.process("A")
        for invalid in ("AB!", "AA", "AAAA", "AAß", 123, False):
            before = machine.positions
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                machine.reset(invalid)
            self.assertEqual(machine.positions, before)

    def test_invalid_whole_message_cannot_partially_advance_machine(self):
        # Put valid letters before each invalid suffix to catch incremental validation.
        for suffix in ("!", "1", " ", "\t", "\n", "é", "ſ", "ı", "ß", "Ａ"):
            with self.subTest(suffix=suffix):
                machine = Machine(MachineKey(positions="ADU"))
                before = machine.positions
                with self.assertRaises(ValueError):
                    machine.process("ABC" + suffix)
                self.assertEqual(machine.positions, before)
        machine = Machine(MachineKey())
        for value in (None, 123, b"ABC"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                machine.process(value)
            self.assertEqual(machine.positions, "AAA")

    def test_single_key_and_trace_validation_happens_before_stepping(self):
        for operation in ("key_press", "trace_letter"):
            for text in ("", "AB", "!", "ß", "ſ", None):
                with self.subTest(operation=operation, text=text):
                    machine = Machine(MachineKey(positions="ADU"))
                    with self.assertRaises(ValueError):
                        getattr(machine, operation)(text)
                    self.assertEqual(machine.positions, "ADU")

    def test_each_rotor_wraps_z_to_a_when_it_moves(self):
        for initial, expected in (("AAZ", "AAA"), ("AZV", "AAW"), ("ZEA", "AFB")):
            with self.subTest(initial=initial):
                machine = Machine(MachineKey(positions=initial))
                machine.key_press("A")
                self.assertEqual(machine.positions, expected)

    def test_middle_double_step_is_decided_from_pre_key_windows(self):
        for rings in ("AAA", "BUL", "ZZZ"):
            with self.subTest(rings=rings):
                machine = Machine(MachineKey(positions="ADU", rings=rings))
                traces = [machine.trace_letter("A") for _ in range(3)]
                self.assertEqual([trace.after for trace in traces], ["ADV", "AEW", "BFX"])
                self.assertEqual(
                    [trace.steps for trace in traces],
                    [(False, False, True), (False, True, True), (True, True, True)],
                )

    def test_every_fast_rotor_uses_its_visible_notch(self):
        # Derived from the documented Q/E/V/J/Z visible-window mechanics.
        for fast in ROTORS:
            remaining = [name for name in ROTORS if name != fast]
            rotors = (remaining[0], remaining[1], fast)
            notch = ascii_uppercase[ROTORS[fast].notch]
            for rings in ("AAA", "BUL"):
                with self.subTest(fast=fast, rings=rings):
                    machine = Machine(
                        MachineKey(rotors=rotors, rings=rings, positions="AA" + notch)
                    )
                    trace = machine.trace_letter("A")
                    self.assertEqual(trace.steps, (False, True, True))
                    self.assertEqual(trace.after[:2], "AB")

    def test_middle_at_notch_steps_even_when_fast_rotor_is_not_at_notch(self):
        for middle in ROTORS:
            remaining = [name for name in ROTORS if name != middle]
            positions = "A" + ascii_uppercase[ROTORS[middle].notch] + "A"
            with self.subTest(middle=middle):
                machine = Machine(
                    MachineKey(rotors=(remaining[0], middle, remaining[1]), positions=positions)
                )
                trace = machine.trace_letter("A")
                self.assertEqual(trace.steps, (True, True, True))

    def test_first_key_trace_records_pre_step_and_complete_contact_path(self):
        trace = Machine(MachineKey()).trace_letter("a")
        self.assertEqual((trace.input_letter, trace.output_letter), ("A", "B"))
        self.assertEqual(
            (trace.before, trace.after, trace.steps), ("AAA", "AAB", (False, False, True))
        )
        self.assertEqual(
            [(stage.component, stage.direction) for stage in trace.path],
            [
                ("plugboard", "in"),
                ("III", "forward"),
                ("II", "forward"),
                ("I", "forward"),
                ("B", "reflect"),
                ("I", "reverse"),
                ("II", "reverse"),
                ("III", "reverse"),
                ("plugboard", "out"),
            ],
        )
        # Hand-worked first-key contact path using the published wiring tables.
        self.assertEqual(
            [trace.path[0].input_letter] + [stage.output_letter for stage in trace.path],
            list("AACDFSSEBB"),
        )

    def test_trace_and_untraced_processing_agree_without_changing_initial_key(self):
        key = MachineKey(positions="ADU", rings="BUL", reflector="C", plugboard=("AB", "XY"))
        traced, ordinary = Machine(key), Machine(key)
        for letter in "HELLOWORLD":
            before = traced.positions
            trace = traced.trace_letter(letter)
            self.assertEqual(trace.output_letter, ordinary.key_press(letter))
            self.assertEqual(trace.before, before)
            self.assertEqual(trace.after, traced.positions)
            self.assertEqual(traced.positions, ordinary.positions)
            self.assertEqual(len(trace.path), 9)
            self.assertEqual(trace.path[0].input_letter, letter)
            self.assertEqual(trace.path[-1].output_letter, trace.output_letter)
            for earlier, later in zip(trace.path, trace.path[1:], strict=False):
                self.assertEqual(earlier.output_letter, later.input_letter)
        self.assertEqual(traced.key, key)

    def test_trace_records_are_frozen(self):
        trace = Machine(MachineKey()).trace_letter("A")
        with self.assertRaises(FrozenInstanceError):
            trace.after = "ZZZ"
        with self.assertRaises(FrozenInstanceError):
            trace.path[0].output_letter = "Z"


if __name__ == "__main__":
    unittest.main()

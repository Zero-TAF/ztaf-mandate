"""Unit tests for the registered constraint comparison rules (spec 3a)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ztaf_mandate.constraints import (  # noqa: E402
    ConstraintError,
    check_attenuation,
    grade_rank,
)


def set_c(value):
    return {"type": "resource-scope", "value": value}


def budget(amount, unit="EUR"):
    return {"type": "budget", "value": {"unit": unit, "amount": amount}}


def pbound(field, op, bound):
    return {"type": "parameter-bound", "value": {"field": field, "op": op, "bound": bound}}


class TestSetRules(unittest.TestCase):
    def test_subset_ok(self):
        ok, _ = check_attenuation([set_c(["a", "b"])], [set_c(["a"])])
        self.assertTrue(ok)

    def test_superset_fails(self):
        ok, reason = check_attenuation([set_c(["a"])], [set_c(["a", "b"])])
        self.assertFalse(ok)
        self.assertIn("attenuation", reason)

    def test_parent_type_missing_in_child_fails(self):
        ok, reason = check_attenuation([set_c(["a"])], [])
        self.assertFalse(ok)
        self.assertIn("missing in child", reason)

    def test_child_adds_new_type_is_refinement(self):
        ok, _ = check_attenuation([set_c(["a"])], [set_c(["a"]), budget(100)])
        self.assertTrue(ok)


class TestBudgetRules(unittest.TestCase):
    def test_smaller_ok(self):
        ok, _ = check_attenuation([budget(5000)], [budget(1000)])
        self.assertTrue(ok)

    def test_larger_fails(self):
        ok, _ = check_attenuation([budget(5000)], [budget(9000)])
        self.assertFalse(ok)

    def test_unit_mismatch_is_error(self):
        ok, reason = check_attenuation([budget(5000, "EUR")], [budget(10, "USD")])
        self.assertFalse(ok)
        self.assertIn("comparison error", reason)


class TestParameterBoundRules(unittest.TestCase):
    def test_max_lower_ok(self):
        ok, _ = check_attenuation([pbound("amount", "max", 500)], [pbound("amount", "max", 100)])
        self.assertTrue(ok)

    def test_max_higher_fails(self):
        ok, _ = check_attenuation([pbound("amount", "max", 500)], [pbound("amount", "max", 900)])
        self.assertFalse(ok)

    def test_set_subset_ok(self):
        ok, _ = check_attenuation([pbound("target", "set", ["a", "b"])], [pbound("target", "set", ["a"])])
        self.assertTrue(ok)

    def test_different_op_is_missing_pair_violation(self):
        # Registered rule: each parent (field, op) pair must have a child
        # counterpart. (amount, min) alone leaves the parent's (amount, max)
        # pair unmatched — an attenuation violation, not a comparison error.
        ok, reason = check_attenuation([pbound("amount", "max", 500)], [pbound("amount", "min", 10)])
        self.assertFalse(ok)
        self.assertIn("attenuation violation", reason)
        self.assertIn("missing in child", reason)

    def test_new_field_is_refinement(self):
        # Child keeps the parent pair and adds a new one: a refinement.
        ok, _ = check_attenuation(
            [pbound("amount", "max", 500)],
            [pbound("amount", "max", 100), pbound("retries", "max", 2)],
        )
        self.assertTrue(ok)

    def test_dropped_parent_pair_is_violation(self):
        # Child replaces the parent pair with a different field: the parent's
        # (amount, max) axis is dropped — an attenuation violation.
        ok, reason = check_attenuation(
            [pbound("amount", "max", 500)], [pbound("retries", "max", 2)]
        )
        self.assertFalse(ok)
        self.assertIn("missing in child", reason)


class TestGradeOrder(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(grade_rank("TG-1"), grade_rank("TG-2"))
        self.assertLess(grade_rank("TG-3"), grade_rank("TG-4"))

    def test_unknown_grade_raises(self):
        with self.assertRaises(ConstraintError):
            grade_rank("TG-9")


if __name__ == "__main__":
    unittest.main()

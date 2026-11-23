"""The registered constraint vocabulary and its comparison rules.

The vocabulary and the comparison rules (``C ⊑ P``: the child constraint is
at least as strict as the parent's) are registered normatively in ztaf-spec,
mandate format document section 3a. This module is the reference
implementation of exactly those rules; the two must move together by change
request.
"""

from __future__ import annotations

from typing import Any, Optional

SET_TYPES = {
    "outcome-scope",
    "resource-scope",
    "data-class",
    "egress-destination",
}

GRADE_ORDER = ["TG-0", "TG-1", "TG-2", "TG-3", "TG-4"]


class ConstraintError(Exception):
    pass


def grade_rank(grade: str) -> int:
    if grade not in GRADE_ORDER:
        raise ConstraintError(f"unknown grade: {grade}")
    return GRADE_ORDER.index(grade)


def _compare_set(parent: Any, child: Any) -> bool:
    return set(child) <= set(parent)


def _compare_budget(parent: Any, child: Any) -> bool:
    if parent.get("unit") != child.get("unit"):
        raise ConstraintError("budget compared across different units")
    return child["amount"] <= parent["amount"]


def _compare_rate_cap(parent: Any, child: Any) -> bool:
    if parent.get("window") != child.get("window"):
        raise ConstraintError("rate-cap compared across different windows")
    return child["max_actions"] <= parent["max_actions"]


def _compare_temporal_window(parent: Any, child: Any) -> bool:
    if parent.get("not_before") and child.get("not_before"):
        if child["not_before"] < parent["not_before"]:
            return False
    if parent.get("not_after") and child.get("not_after"):
        if child["not_after"] > parent["not_after"]:
            return False
    return True


def _compare_parameter_bound(parent: Any, child: Any) -> bool:
    """Compare one (field, op) pair only; parent/child are the full constraint
    objects. Grouping by pair happens in check_attenuation: the child may add
    new pairs as refinements (spec 3a)."""
    op = parent["value"]["op"]
    if op == "max":
        return child["value"]["bound"] <= parent["value"]["bound"]
    if op == "min":
        return child["value"]["bound"] >= parent["value"]["bound"]
    if op == "set":
        return set(child["value"]["bound"]) <= set(parent["value"]["bound"])
    raise ConstraintError(f"unknown parameter-bound op: {op}")


_COMPARATORS = {
    "budget": _compare_budget,
    "rate-cap": _compare_rate_cap,
    "temporal-window": _compare_temporal_window,
    "parameter-bound": _compare_parameter_bound,
}


def _compare_same_type(parent: Any, child: Any) -> bool:
    if parent["type"] in SET_TYPES:
        return _compare_set(parent["value"], child["value"])
    if parent["type"] in _COMPARATORS:
        return _COMPARATORS[parent["type"]](parent["value"], child["value"])
    raise ConstraintError(f"unknown constraint type: {parent['type']}")


def check_attenuation(
    parent_constraints: list[dict], child_constraints: list[dict]
) -> tuple[bool, Optional[str]]:
    """Check MAN-4 as registered in the spec (section 3a).

    Every parent constraint type must appear in the child with an
    at-least-as-strict value; a child constraint whose type the parent lacks
    is a permitted refinement. ``parameter-bound`` is grouped by (field, op)
    pair: each parent pair must have a child counterpart satisfying the
    comparison, and child-only pairs are refinements. Returns (ok, reason).
    """
    parent_by_type = {c["type"]: c for c in parent_constraints if c["type"] != "parameter-bound"}
    child_by_type = {c["type"]: c for c in child_constraints if c["type"] != "parameter-bound"}
    for ptype, pconstraint in parent_by_type.items():
        if ptype not in child_by_type:
            return False, f"attenuation violation: parent constraint type missing in child: {ptype}"
        try:
            if not _compare_same_type(pconstraint, child_by_type[ptype]):
                return False, f"attenuation violation: child constraint looser than parent: {ptype}"
        except ConstraintError as exc:
            return False, f"constraint comparison error ({ptype}): {exc}"

    known_types = SET_TYPES | set(_COMPARATORS)
    for ctype in child_by_type:
        if ctype not in known_types:
            return False, f"unknown constraint type: {ctype}"

    # parameter-bound: group parent and child pairs by (field, op).
    parent_pairs = {
        (c["value"]["field"], c["value"]["op"]): c
        for c in parent_constraints if c["type"] == "parameter-bound"
    }
    child_pairs = {
        (c["value"]["field"], c["value"]["op"]): c
        for c in child_constraints if c["type"] == "parameter-bound"
    }
    for pair, pconstraint in parent_pairs.items():
        if pair not in child_pairs:
            return False, (f"attenuation violation: parent parameter-bound missing in child: "
                           f"{pair[0]}/{pair[1]}")
        try:
            if not _compare_parameter_bound(pconstraint, child_pairs[pair]):
                return False, (f"attenuation violation: child parameter-bound looser than parent: "
                               f"{pair[0]}/{pair[1]}")
        except ConstraintError as exc:
            return False, f"constraint comparison error (parameter-bound {pair[0]}/{pair[1]}): {exc}"

    return True, None

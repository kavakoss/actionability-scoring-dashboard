"""Tests for the AHP weight matrices and generated weights.json."""

from ahp.core import ahp
from ahp.matrices import CATEGORY_COMPARISONS, CATEGORY_NAMES, FIELD_MATRICES, compute_all
from field_metadata import FIELD_META
from scoring import load_weights


def test_category_matrix_is_consistent():
    result = ahp(CATEGORY_NAMES, CATEGORY_COMPARISONS)
    assert result["cr"] < 0.10


def test_all_field_matrices_are_consistent():
    for category, spec in FIELD_MATRICES.items():
        result = ahp(spec["names"], spec["comparisons"])
        assert result["cr"] < 0.10, f"{category} CR={result['cr']:.4f}"


def test_priority_vectors_sum_to_one():
    for category, spec in FIELD_MATRICES.items():
        result = ahp(spec["names"], spec["comparisons"])
        assert abs(sum(result["priority"].values()) - 1.0) < 1e-9, category


def test_matrices_cover_exactly_the_metadata_fields():
    for category, fields in FIELD_META.items():
        assert set(fields.keys()) == set(FIELD_MATRICES[category]["names"]), category


def test_global_weights_sum_to_one():
    weights = load_weights()
    total = sum(
        field["global_weight"]
        for category in weights["categories"].values()
        for field in category["fields"].values()
    )
    # weights.json stores six-decimal display values; allow rounding headroom
    assert abs(total - 1.0) < 1e-4


def test_generated_weights_match_matrices():
    computed = compute_all()
    weights = load_weights()
    for category, spec in FIELD_MATRICES.items():
        for name in spec["names"]:
            expected = computed["fields"][category]["global"][name]
            actual = weights["categories"][category]["fields"][name]["global_weight"]
            assert abs(expected - actual) < 1e-6, f"{category}.{name}"
        assert weights["categories"][category]["consistent"] is True


def test_category_matrix_stored_in_weights_matches_computation():
    computed = compute_all()
    weights = load_weights()
    for name in CATEGORY_NAMES:
        expected = computed["category"]["priority"][name]
        actual = weights["categories"][name]["weight"]
        assert abs(expected - actual) < 1e-6, name

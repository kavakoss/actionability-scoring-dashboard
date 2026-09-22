"""Core AHP computation (Saaty's eigenvector method).

Reference:
    Saaty, T. L. (1980). The Analytic Hierarchy Process. McGraw-Hill.
    Saaty, T. L. (2008). Decision making with the analytic hierarchy process.
    Int. J. Services Sciences, 1(1), 83-98.
"""

from __future__ import annotations

import numpy as np

RI_TABLE = {
    1: 0.00,
    2: 0.00,
    3: 0.58,
    4: 0.90,
    5: 1.12,
    6: 1.24,
    7: 1.32,
    8: 1.41,
    9: 1.45,
    10: 1.49,
}


def pairwise_matrix(names: list, comparisons: dict) -> np.ndarray:
    """Build an n x n reciprocal matrix from upper-triangle comparisons."""
    index = {name: i for i, name in enumerate(names)}
    size = len(names)
    matrix = np.ones((size, size), dtype=float)
    for (left, right), value in comparisons.items():
        i, j = index[left], index[right]
        matrix[i, j] = float(value)
        matrix[j, i] = 1.0 / float(value)
    return matrix


def ahp(names: list, comparisons: dict) -> dict:
    """Priority vector, lambda max, consistency index and ratio."""
    matrix = pairwise_matrix(names, comparisons)
    column_sum = matrix.sum(axis=0)
    normalized = matrix / column_sum
    priority = normalized.mean(axis=1)

    weighted_sum = matrix.dot(priority)
    lambda_max = float((weighted_sum / priority).mean())

    size = len(names)
    ci = (lambda_max - size) / (size - 1) if size > 1 else 0.0
    ri = RI_TABLE.get(size, 1.49)
    cr = ci / ri if ri else 0.0

    return {
        "names": names,
        "matrix": matrix,
        "priority": {name: float(value) for name, value in zip(names, priority)},
        "lambda_max": lambda_max,
        "ci": ci,
        "cr": cr,
        "consistent": cr < 0.10,
    }


def matrix_markdown(result: dict, decimals: int = 4) -> str:
    names = result["names"]
    matrix = result["matrix"]
    header = "| | " + " | ".join(names) + " |"
    separator = "|---" * (len(names) + 1) + "|"
    rows = [header, separator]
    for i, name in enumerate(names):
        cells = " | ".join(f"{matrix[i, j]:.{decimals}f}" for j in range(len(names)))
        rows.append(f"| **{name}** | {cells} |")
    return "\n".join(rows)

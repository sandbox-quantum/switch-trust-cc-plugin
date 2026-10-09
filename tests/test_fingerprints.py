"""Golden-vector parity tests for hooks/ccusage/fingerprints.py.

make_model_fingerprint / make_agent_fingerprint are local reimplementations
of the backend's fingerprinting algorithm (see fingerprints.py's module
docstring for why). Correctness is pinned against the same golden vector
files the canonical implementation is pinned against, rather than by sharing
code.
"""

from __future__ import annotations

import json
import os
import sys

_HOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "hooks")
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

from ccusage.fingerprints import (  # noqa: E402
    make_agent_fingerprint,
    make_model_fingerprint,
)

_TESTDATA_DIR = os.path.join(os.path.dirname(__file__), "testdata")
AGENT_GOLDEN_PATH = os.path.join(_TESTDATA_DIR, "agent_fingerprint", "golden.json")
MODEL_GOLDEN_PATH = os.path.join(_TESTDATA_DIR, "model_fingerprint", "golden.json")


def test_agent_fingerprint_golden_vectors() -> None:
    """make_agent_fingerprint matches every pinned golden vector."""
    with open(AGENT_GOLDEN_PATH) as f:
        vectors = json.load(f)["vectors"]
    assert vectors, "golden vectors must not be empty"
    for v in vectors:
        fp = make_agent_fingerprint(v["name"])
        assert fp == v["expected_fingerprint"], (
            f"agent fingerprint mismatch for {v['name']!r}: got {fp}"
        )


def test_model_fingerprint_golden_vectors() -> None:
    """make_model_fingerprint matches every pinned golden vector."""
    with open(MODEL_GOLDEN_PATH) as f:
        vectors = json.load(f)["vectors"]
    assert vectors, "golden vectors must not be empty"
    for v in vectors:
        fp = make_model_fingerprint(v["manufacturer"], v["name"])
        assert fp == v["expected_fingerprint"], (
            f"model fingerprint mismatch for {v['manufacturer']!r}/{v['name']!r}: got {fp}"
        )

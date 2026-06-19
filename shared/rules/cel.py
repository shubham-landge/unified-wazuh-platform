"""CEL rule engine for safe, declarative, analyst-editable expressions.

Uses ``cel-python`` (celpy) to compile and evaluate Common Expression Language
(CEL) expressions against an activation map built from alerts and context.

Activation schema (keys available in CEL expressions as top-level identifiers):

  ``alert``         Map      Wazuh alert fields
    .rule_level       int     Rule level (0–15)
    .rule_id          int     Matched rule ID
    .rule_groups      list    Rule group memberships
  ``ti``            Map      Threat‑intel enrichment
    .is_known_bad     bool    Known malicious indicator
    .is_kev           bool    On CISA KEV list
  ``ueba``          Map      User & entity behaviour analytics
    .zscore           float   Anomaly z‑score
  ``asset``         Map      Asset inventory
    .criticality      int     Criticality rating (1–10)
  ``geo``           Map      Geolocation
    .impossible_travel bool   Impossible‑travel flag
  ``vuln``          Map      Vulnerability scanning
    .matched          bool    Active vulnerability found
  ``score``         float    Composite risk score (0–100)

Usage::

    prog = compile_rule('alert.rule_level >= 7 && ti.is_known_bad')
    activation = build_activation(
        alert={"rule_level": 10, "rule_id": 101},
        ti={"is_known_bad": True},
    )
    result = evaluate(prog, activation)  # → True
"""

from __future__ import annotations

import functools
import logging

import celpy
from celpy import celtypes, json_to_cel

__all__ = ["compile_rule", "evaluate", "validate", "build_activation"]

logger = logging.getLogger(__name__)

# Module-level CEL environment reused across all compilations.
_env = celpy.Environment()


@functools.lru_cache(maxsize=256)
def compile_rule(expr: str) -> celpy.InterpretedRunner:
    """Compile a CEL expression into a cached, executable program.

    Raises:
        celpy.CELParseError: If the expression is syntactically invalid.
    """
    ast = _env.compile(expr)
    return _env.program(ast)


def evaluate(
    prog: celpy.InterpretedRunner,
    activation: dict,
) -> bool:
    """Evaluate a compiled CEL program and return a boolean.

    Raises:
        celpy.CELEvalError: On runtime evaluation errors (missing key, type
            mismatch, etc.).
    """
    return bool(prog.evaluate(activation))


def validate(expr: str) -> str | None:
    """Return ``None`` for a valid CEL expression, or an error message string."""
    try:
        compile_rule(expr)
        return None
    except celpy.CELParseError as e:
        return str(e)
    except Exception as e:
        logger.warning("Unexpected validation error for %r: %s", expr, e)
        return str(e)


def build_activation(
    alert: dict | None = None,
    ti: dict | None = None,
    ueba: dict | None = None,
    asset: dict | None = None,
    geo: dict | None = None,
    vuln: dict | None = None,
    score: float | int | None = None,
) -> dict:
    """Build a celpy-typed activation dict for ``evaluate()``.

    Parameters
    ----------
    alert
        Dict with fields documented under the ``alert`` key above.
    ti, ueba, asset, geo, vuln
        Dicts with fields documented under their respective keys above.
    score
        Numeric risk score (converted to ``DoubleType`` internally).
    """
    activation: dict = {}
    if alert is not None:
        activation["alert"] = json_to_cel(alert)
    if ti is not None:
        activation["ti"] = json_to_cel(ti)
    if ueba is not None:
        activation["ueba"] = json_to_cel(ueba)
    if asset is not None:
        activation["asset"] = json_to_cel(asset)
    if geo is not None:
        activation["geo"] = json_to_cel(geo)
    if vuln is not None:
        activation["vuln"] = json_to_cel(vuln)
    if score is not None:
        activation["score"] = json_to_cel(score)
    return activation

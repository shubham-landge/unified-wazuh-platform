"""Tests for the CEL rule engine."""
import pytest

from shared.rules.cel import compile_rule, evaluate, validate, build_activation


class TestCompileAndEvaluate:
    def test_simple_comparison(self):
        prog = compile_rule("alert.rule_level > 3")
        activation = build_activation(alert={"rule_level": 7})
        assert evaluate(prog, activation) is True

        activation = build_activation(alert={"rule_level": 2})
        assert evaluate(prog, activation) is False

    def test_nested_field_access(self):
        prog = compile_rule("ti.is_known_bad")
        activation = build_activation(ti={"is_known_bad": True})
        assert evaluate(prog, activation) is True

    def test_compound_and_or(self):
        expr = "alert.rule_level >= 7 && ti.is_known_bad || asset.criticality >= 8"
        prog = compile_rule(expr)

        # AND path
        assert evaluate(prog, build_activation(
            alert={"rule_level": 10}, ti={"is_known_bad": True},
        )) is True

        # OR fallback
        assert evaluate(prog, build_activation(
            alert={"rule_level": 3}, ti={"is_known_bad": False},
            asset={"criticality": 9},
        )) is True

        # Neither
        assert evaluate(prog, build_activation(
            alert={"rule_level": 3}, ti={"is_known_bad": False},
            asset={"criticality": 3},
        )) is False

    def test_has_macro(self):
        """has() checks field existence."""
        prog = compile_rule("has(alert.rule_level)")
        assert evaluate(prog, build_activation(alert={"rule_level": 5})) is True
        assert evaluate(prog, build_activation(alert={})) is False

    def test_in_operator(self):
        prog = compile_rule("alert.rule_id in [100, 200, 300]")
        assert evaluate(prog, build_activation(alert={"rule_id": 100})) is True
        assert evaluate(prog, build_activation(alert={"rule_id": 999})) is False

    def test_float_comparison(self):
        prog = compile_rule("ueba.zscore > 2.5")
        activation = build_activation(ueba={"zscore": 3.1})
        assert evaluate(prog, activation) is True

    def test_score_field(self):
        prog = compile_rule("score >= 80.0")
        activation = build_activation(score=85.0)
        assert evaluate(prog, activation) is True

        activation = build_activation(score=50.0)
        assert evaluate(prog, activation) is False

    def test_full_activation_schema(self):
        """All schema keys present simultaneously."""
        activation = build_activation(
            alert={"rule_level": 10, "rule_id": 101, "rule_groups": ["syslog", "auth"]},
            ti={"is_known_bad": True, "is_kev": False},
            ueba={"zscore": 3.5},
            asset={"criticality": 8},
            geo={"impossible_travel": False},
            vuln={"matched": True},
            score=85.0,
        )
        expr = (
            "alert.rule_level >= 7 && ti.is_known_bad"
            " && (ueba.zscore > 2.5 || asset.criticality >= 8)"
        )
        prog = compile_rule(expr)
        assert evaluate(prog, activation) is True


class TestValidate:
    def test_valid_expr_returns_none(self):
        assert validate("alert.rule_level > 3") is None

    def test_malformed_expr_returns_error(self):
        error = validate("invalid {{{ syntax")
        assert error is not None
        assert isinstance(error, str)

    def test_incomplete_expr_returns_error(self):
        error = validate("alert.rule_level >")
        assert error is not None

    def test_validate_does_not_cache_error(self):
        """A corrected expression should pass after a malformed attempt."""
        assert validate("broken !!") is not None
        assert validate("alert.rule_level > 3") is None


class TestCaching:
    def test_same_expr_returns_same_object(self):
        prog1 = compile_rule("alert.rule_level > 3")
        prog2 = compile_rule("alert.rule_level > 3")
        assert prog1 is prog2

    def test_different_expr_different_object(self):
        prog1 = compile_rule("alert.rule_level > 3")
        prog2 = compile_rule("alert.rule_level > 5")
        assert prog1 is not prog2

    def test_build_activation_produces_fresh_dicts(self):
        a1 = build_activation(alert={"rule_level": 7})
        a2 = build_activation(alert={"rule_level": 7})
        assert a1 == a2
        assert a1 is not a2


class TestRuntimeErrors:
    def test_missing_key_raises(self):
        prog = compile_rule("alert.rule_level > 3")
        with pytest.raises(Exception):  # celpy.CELEvalError
            evaluate(prog, {})

    def test_type_mismatch_raises(self):
        prog = compile_rule("alert.rule_level > 3")
        with pytest.raises(Exception):
            evaluate(prog, build_activation(alert={"rule_level": "not_a_number"}))

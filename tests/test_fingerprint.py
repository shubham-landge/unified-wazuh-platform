"""Tests for shared.enrichment.fingerprint — SHA-256 based alert dedup.

All tests are pure unit tests — no DB, no Redis, no network required.
"""
from __future__ import annotations

import pytest

from shared.enrichment.fingerprint import (
    compute_fingerprint,
    get_default_fingerprint_fields,
)


class TestComputeFingerprint:
    """Deterministic fingerprint computation."""

    def test_partial_selects_only_given_fields(self):
        alert = {"rule_id": 100001, "source_ip": "10.0.0.1", "agent_id": "001", "extra": "ignored"}
        fp = compute_fingerprint(alert, fields=["rule_id", "source_ip", "agent_id"], mode="partial")
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex digest

    def test_partial_excludes_fields_not_listed(self):
        alert = {"rule_id": 100001, "source_ip": "10.0.0.1", "agent_id": "001"}
        fp_small = compute_fingerprint(alert, fields=["rule_id"], mode="partial")
        fp_full_fields = compute_fingerprint(alert, fields=["rule_id", "source_ip", "agent_id"], mode="partial")
        assert fp_small != fp_full_fields  # different field sets → different hashes

    def test_same_alert_same_fingerprint(self):
        alert = {"rule_id": 100001, "source_ip": "10.0.0.1", "agent_id": "001"}
        fp1 = compute_fingerprint(alert, fields=["rule_id", "source_ip"], mode="partial")
        fp2 = compute_fingerprint(alert, fields=["rule_id", "source_ip"], mode="partial")
        assert fp1 == fp2

    def test_different_alert_different_fingerprint(self):
        a1 = {"rule_id": 100001, "source_ip": "10.0.0.1"}
        a2 = {"rule_id": 100002, "source_ip": "10.0.0.1"}
        fp1 = compute_fingerprint(a1, fields=["rule_id", "source_ip"], mode="partial")
        fp2 = compute_fingerprint(a2, fields=["rule_id", "source_ip"], mode="partial")
        assert fp1 != fp2

    def test_full_includes_all_non_null_fields(self):
        alert = {"rule_id": 100001, "source_ip": "10.0.0.1", "agent_id": None}
        fp = compute_fingerprint(alert, mode="full")
        assert isinstance(fp, str)
        assert len(fp) == 64
        # agent_id is None so it should not appear in the serialised payload
        # We verify by checking that adding a non-None field changes the hash.
        alert2 = {**alert, "agent_id": "001"}
        fp2 = compute_fingerprint(alert2, mode="full")
        assert fp != fp2

    def test_full_vs_partial_order_does_not_matter(self):
        # Dict key order should not affect the fingerprint (sort_keys=True).
        a1 = {"agent_id": "001", "rule_id": 100001, "source_ip": "10.0.0.1"}
        a2 = {"source_ip": "10.0.0.1", "agent_id": "001", "rule_id": 100001}
        fp1 = compute_fingerprint(a1, fields=["rule_id", "source_ip", "agent_id"], mode="partial")
        fp2 = compute_fingerprint(a2, fields=["rule_id", "source_ip", "agent_id"], mode="partial")
        assert fp1 == fp2

    def test_orm_like_object(self):
        """Fingerprint works on object-attributed data (simulating an ORM instance)."""
        class FakeAlert:
            rule_id = 100001
            source_ip = "10.0.0.1"
            agent_id = "001"
            _internal = "skip"

        alert = FakeAlert()
        fp = compute_fingerprint(alert, fields=["rule_id", "source_ip", "agent_id"], mode="partial")
        assert len(fp) == 64
        # Same data as dict should produce same fingerprint
        fp_dict = compute_fingerprint(
            {"rule_id": 100001, "source_ip": "10.0.0.1", "agent_id": "001"},
            fields=["rule_id", "source_ip", "agent_id"],
            mode="partial",
        )
        assert fp == fp_dict

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="Unknown fingerprint mode"):
            compute_fingerprint({"rule_id": 1}, mode="invalid")


class TestDefaultFingerprintFields:
    """Per-source default field lists."""

    def test_wazuh_defaults(self):
        fields = get_default_fingerprint_fields("wazuh")
        assert fields == ["rule_id", "source_ip", "agent_id"]

    def test_unknown_source_falls_back(self):
        fields = get_default_fingerprint_fields("unknown_source")
        assert fields == ["rule_id", "source_ip"]

    def test_entra_id_defaults(self):
        fields = get_default_fingerprint_fields("entra_id")
        assert "event_id" in fields
        assert "source_ip" in fields
        assert "user_name" in fields

    def test_network_firewall_defaults(self):
        fields = get_default_fingerprint_fields("network_firewall")
        assert "source_ip" in fields
        assert "destination_ip" in fields
        assert "destination_port" in fields
        assert "protocol" in fields

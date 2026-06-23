"""Test UEBA detector import correctness in triage_worker.

This validates that shared.ueba.detector exports process_alert (not the
old name analyze_alert) and that the function signature matches what
triage_worker.py calls at line 482-483.
"""
import inspect
import pytest


class TestUEBAImport:
    """process_alert is the canonical export — analyze_alert must not exist."""

    def test_process_alert_is_importable(self):
        from shared.ueba.detector import process_alert
        assert callable(process_alert)

    def test_analyze_alert_does_not_exist(self):
        with pytest.raises(ImportError):
            from shared.ueba.detector import analyze_alert  # noqa: F811

    def test_process_alert_signature(self):
        from shared.ueba.detector import process_alert
        sig = inspect.signature(process_alert)
        params = list(sig.parameters.keys())
        assert params == ["session", "alert", "tenant_id"], (
            f"Expected parameters (session, alert, tenant_id), got {params}"
        )

    def test_triage_worker_import_path(self):
        """The exact lazy-import used inside TriageWorker.process_message()."""
        from shared.ueba.detector import process_alert
        assert callable(process_alert)

    def test_triage_worker_calling_convention(self):
        """Verify the call pattern used in triage_worker.py line 482-483 compiles."""
        from shared.ueba.detector import process_alert
        # Signature must accept (session, alert, tenant_id) as positional args
        sig = inspect.signature(process_alert)
        sig.bind(session="s", alert="a", tenant_id="t")

"""Tests for the alert/incident/kill-chain state machine."""
from unittest.mock import MagicMock

import pytest

from shared.state.machine import (
    ALERT_TRANSITIONS,
    INCIDENT_TRANSITIONS,
    KILLCHAIN_TRANSITIONS,
    allowed_transitions,
    AlertState,
    IncidentState,
    KillChainStage,
    TransitionAudit,
    transition,
)


class TestAlertTransitions:
    def test_valid_alert_sequence(self):
        """Follow the happy path: new → enriched → triaged → auto_closed."""
        assert transition(AlertState.NEW, AlertState.ENRICHED) is True
        assert transition(AlertState.ENRICHED, AlertState.TRIAGED) is True
        assert transition(AlertState.TRIAGED, AlertState.AUTO_CLOSED) is True

    def test_triaged_to_escalated_or_suppressed(self):
        """Triaged can branch to escalated or suppressed."""
        assert transition(AlertState.TRIAGED, AlertState.ESCALATED) is True
        assert transition(AlertState.TRIAGED, AlertState.SUPPRESSED) is True

    def test_terminal_states_reject_all_outgoing(self):
        """Terminal alert states have no outgoing transitions."""
        for terminal in (AlertState.AUTO_CLOSED, AlertState.ESCALATED, AlertState.SUPPRESSED):
            for target in AlertState:
                if target is terminal:
                    continue
                assert transition(terminal, target) is False

    def test_skip_stage_blocked(self):
        """Cannot skip a stage (e.g. new → triaged)."""
        assert transition(AlertState.NEW, AlertState.TRIAGED) is False
        assert transition(AlertState.NEW, AlertState.AUTO_CLOSED) is False
        assert transition(AlertState.ENRICHED, AlertState.ESCALATED) is False

    def test_reverse_transition_blocked(self):
        """Cannot move backwards."""
        assert transition(AlertState.ENRICHED, AlertState.NEW) is False
        assert transition(AlertState.TRIAGED, AlertState.ENRICHED) is False

    def test_unknown_state_pair(self):
        """From a state not in the map (should not happen in practice)."""
        result = transition("unknown", AlertState.NEW, allowed={})
        assert result is False


class TestIncidentTransitions:
    def test_valid_incident_sequence(self):
        """Follow the happy path: open → advancing → contained → closed."""
        assert transition(IncidentState.OPEN, IncidentState.ADVANCING) is True
        assert transition(IncidentState.ADVANCING, IncidentState.CONTAINED) is True
        assert transition(IncidentState.CONTAINED, IncidentState.CLOSED) is True

    def test_open_can_close_directly(self):
        """Open may be closed directly without going through advancing."""
        assert transition(IncidentState.OPEN, IncidentState.CLOSED) is True

    def test_advancing_can_close_directly(self):
        """Advancing may be closed directly without containment."""
        assert transition(IncidentState.ADVANCING, IncidentState.CLOSED) is True

    def test_skip_stage_blocked(self):
        """Cannot jump ahead (e.g. open → contained)."""
        assert transition(IncidentState.OPEN, IncidentState.CONTAINED) is False

    def test_terminal_closed_rejects_all(self):
        """Closed is terminal."""
        for target in IncidentState:
            if target is IncidentState.CLOSED:
                continue
            assert transition(IncidentState.CLOSED, target) is False

    def test_reverse_blocked(self):
        """Cannot regress."""
        assert transition(IncidentState.CONTAINED, IncidentState.ADVANCING) is False
        assert transition(IncidentState.ADVANCING, IncidentState.OPEN) is False


class TestKillChainTransitions:
    def test_forward_advancement(self):
        """Each stage can advance to the next stage."""
        stages = list(KillChainStage)
        for i in range(len(stages) - 1):
            assert transition(stages[i], stages[i + 1]) is True

    def test_stay_on_same_stage(self):
        """A stage may transition to itself (no-op / stay)."""
        for stage in KillChainStage:
            assert transition(stage, stage) is True

    def test_multistep_advance(self):
        """Can skip intermediate stages forward."""
        assert transition(KillChainStage.RECON, KillChainStage.C2) is True
        assert transition(KillChainStage.WEAPONIZE, KillChainStage.ACTIONS_ON_OBJECTIVE) is True

    def test_regression_blocked(self):
        """Cannot move to an earlier stage."""
        assert transition(KillChainStage.C2, KillChainStage.RECON) is False
        assert transition(KillChainStage.ACTIONS_ON_OBJECTIVE, KillChainStage.INSTALLATION) is False
        assert transition(KillChainStage.DELIVERY, KillChainStage.WEAPONIZE) is False

    def test_terminal_stage_allows_only_self(self):
        """The final stage can only transition to itself."""
        for target in KillChainStage:
            if target is KillChainStage.ACTIONS_ON_OBJECTIVE:
                assert transition(KillChainStage.ACTIONS_ON_OBJECTIVE, target) is True
            else:
                assert transition(KillChainStage.ACTIONS_ON_OBJECTIVE, target) is False


class TestGuardFunctions:
    def test_guard_allows_transition(self):
        """A guard that returns True does not block the transition."""
        guard = MagicMock(return_value=True)
        assert transition(AlertState.NEW, AlertState.ENRICHED, guard_fn=guard) is True
        guard.assert_called_once_with(AlertState.NEW, AlertState.ENRICHED, None)

    def test_guard_blocks_transition(self):
        """A guard that returns False blocks the transition."""
        guard = MagicMock(return_value=False)
        assert transition(AlertState.NEW, AlertState.ENRICHED, guard_fn=guard) is False
        guard.assert_called_once_with(AlertState.NEW, AlertState.ENRICHED, None)

    def test_guard_receives_audit_ctx(self):
        """Guard receives the audit_ctx dict as its third argument."""
        ctx = {"reason": "risk_score > 0.8"}
        guard = MagicMock(return_value=True)
        assert transition(AlertState.TRIAGED, AlertState.ESCALATED, guard_fn=guard, audit_ctx=ctx) is True
        guard.assert_called_once_with(AlertState.TRIAGED, AlertState.ESCALATED, ctx)

    def test_guard_not_called_when_transition_invalid(self):
        """Guard is not invoked when the transition is not in the allowed set."""
        guard = MagicMock(return_value=True)
        assert transition(AlertState.NEW, AlertState.TRIAGED, guard_fn=guard) is False
        guard.assert_not_called()


class TestAuditEmission:
    def test_audit_sink_called_on_success(self):
        """The audit_sink is called with a TransitionAudit on successful transition."""
        audit = MagicMock()
        result = transition(AlertState.NEW, AlertState.ENRICHED, audit_sink=audit)
        assert result is True
        audit.assert_called_once()
        call_arg = audit.call_args[0][0]
        assert isinstance(call_arg, TransitionAudit)
        assert call_arg.old_value == "new"
        assert call_arg.new_value == "enriched"
        assert call_arg.description == "State transition: AlertState.NEW -> AlertState.ENRICHED"

    def test_audit_sink_not_called_on_blocked(self):
        """The audit_sink is not called when the transition is blocked."""
        audit = MagicMock()
        result = transition(AlertState.NEW, AlertState.TRIAGED, audit_sink=audit)
        assert result is False
        audit.assert_not_called()

    def test_audit_sink_not_called_on_guard_rejection(self):
        """The audit_sink is not called when the guard rejects the transition."""
        audit = MagicMock()
        guard = MagicMock(return_value=False)
        result = transition(AlertState.NEW, AlertState.ENRICHED, guard_fn=guard, audit_sink=audit)
        assert result is False
        audit.assert_not_called()

    def test_audit_context_passed_to_event_meta(self):
        """audit_ctx is included in the TransitionAudit event_meta."""
        audit = MagicMock()
        ctx = {"trigger": "timer", "confidence": 0.95}
        transition(AlertState.ENRICHED, AlertState.TRIAGED, audit_ctx=ctx, audit_sink=audit)
        call_arg = audit.call_args[0][0]
        assert call_arg.event_meta == ctx

    def test_audit_meta_is_copy(self):
        """event_meta is a copy, not the original reference."""
        audit = MagicMock()
        ctx = {"key": "value"}
        transition(AlertState.NEW, AlertState.ENRICHED, audit_ctx=ctx, audit_sink=audit)
        call_arg = audit.call_args[0][0]
        assert call_arg.event_meta == ctx
        # Mutation of original should not affect the audit copy
        ctx["key"] = "mutated"
        assert call_arg.event_meta["key"] == "value"

    def test_no_audit_sink_no_error(self):
        """Calling transition without an audit_sink works fine."""
        assert transition(AlertState.NEW, AlertState.ENRICHED) is True


class TestAllowedTransitionsLookup:
    def test_combined_dict_contains_all_machines(self):
        """allowed_transisions contains entries for all three machines."""
        assert AlertState.NEW in allowed_transitions
        assert IncidentState.OPEN in allowed_transitions
        assert KillChainStage.RECON in allowed_transitions

    def test_alert_transitions_exposed(self):
        """Module-level ALERT_TRANSITIONS matches the combined dict for alert states."""
        for state, targets in ALERT_TRANSITIONS.items():
            assert allowed_transitions[state] == targets

    def test_incident_transitions_exposed(self):
        """Module-level INCIDENT_TRANSITIONS matches the combined dict for incident states."""
        for state, targets in INCIDENT_TRANSITIONS.items():
            assert allowed_transitions[state] == targets

    def test_killchain_transitions_exposed(self):
        """Module-level KILLCHAIN_TRANSITIONS matches the combined dict."""
        for state, targets in KILLCHAIN_TRANSITIONS.items():
            assert allowed_transitions[state] == targets

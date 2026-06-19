"""Workflow execution context — step output storage + ``{{ }}`` interpolation."""

from __future__ import annotations

import re
from typing import Any

__all__ = ["WorkflowContext", "interpolate"]

_INTERP_RE = re.compile(r"\{\{(\s*[\w.]+(?:\[[\"']?\w+[\"']?\])*\s*)\}\}")


def _resolve_path(target: dict | list | str | int | float | bool | None, path: str) -> Any:
    """Resolve a dotted-path string against a nested dict/list structure.

    Supports ``steps.my_step.output.subfield`` and
    ``steps.my_step.output[0]`` indexing.
    """
    value: Any = target
    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part, "")
        elif isinstance(value, list):
            try:
                idx = int(part)
                value = value[idx]
            except (ValueError, IndexError):
                return ""
        else:
            return ""
    return value


def interpolate(
    template: str,
    *,
    alert: dict[str, Any] | None = None,
    trigger: dict[str, Any] | None = None,
    step_outputs: dict[str, Any] | None = None,
) -> str:
    """Replace ``{{ path }}`` placeholders with resolved context values.

    Supported prefix groups::

        ``alert.field``          — top-level alert fields
        ``trigger.field``        — trigger activation data
        ``steps.name.output``    — output dict from a prior step
        ``steps.name.output.x``  — nested field in a step output

    Unknown or unresolvable paths are replaced with an empty string.
    """
    sources: dict[str, Any] = {}
    if alert is not None:
        sources["alert"] = alert
    if trigger is not None:
        sources["trigger"] = trigger
    if step_outputs is not None:
        sources["steps"] = step_outputs

    def _replacer(m: re.Match) -> str:
        raw = m.group(1).strip()
        # Find which source prefix matches
        for prefix in ("steps", "alert", "trigger"):
            if raw.startswith(prefix):
                rest = raw[len(prefix) + 1:] if len(raw) > len(prefix) else ""
                source = sources.get(prefix)
                if source is None:
                    return ""
                if not rest:
                    return str(source)
                resolved = _resolve_path(source, rest.lstrip("."))
                return str(resolved) if resolved is not None else ""
        return ""

    return _INTERP_RE.sub(_replacer, template)


class WorkflowContext:
    """Mutable context that accumulates step outputs during a workflow run.

    Typical lifecycle::

        ctx = WorkflowContext(alert=alert, trigger_data=trigger_data)
        ctx.set_step_output("enrich", {"is_malicious": True})
        interp = ctx.interpolate("{{ steps.enrich.output.is_malicious }}")
    """

    def __init__(
        self,
        alert: dict[str, Any] | None = None,
        trigger_data: dict[str, Any] | None = None,
    ) -> None:
        self.alert = alert or {}
        self.trigger_data = trigger_data or {}
        self._step_outputs: dict[str, Any] = {}

    def set_step_output(self, step_name: str, output: Any) -> None:
        """Store the output of a completed step."""
        self._step_outputs[step_name] = {"output": output}

    def get_step_output(self, step_name: str) -> Any:
        """Retrieve raw output of a prior step, or ``None``."""
        entry = self._step_outputs.get(step_name)
        return entry["output"] if entry else None

    @property
    def all_step_outputs(self) -> dict[str, Any]:
        return dict(self._step_outputs)

    def interpolate(self, template: str) -> str:
        """Shortcut for ``interpolate(template, …)`` using current context."""
        return interpolate(
            template,
            alert=self.alert,
            trigger=self.trigger_data,
            step_outputs=self._step_outputs,
        )

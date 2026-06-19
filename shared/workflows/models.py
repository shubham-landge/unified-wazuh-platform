"""Declarative workflow models — Workflow, Trigger, Step, Action."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Action:
    """A builtin action to execute as part of a workflow step.

    ``type`` is one of ``enrich``, ``create_case``, ``gated_containment``,
    ``notify``, or any provider action key.
    """

    type: str
    with_: dict[str, Any] = field(default_factory=dict)


@dataclass
class Step:
    """A single step in a workflow.

    If ``provider`` is set the engine will call the named provider with
    the supplied parameters.  ``actions`` are builtin operations run
    after the provider call (or standalone when no provider is given).
    The optional ``if_`` expression is a CEL string — when it evaluates
    to false the step is skipped.
    """

    name: str
    provider: dict[str, Any] | None = None
    if_: str | None = None
    actions: list[Action] = field(default_factory=list)


@dataclass
class Trigger:
    """Workflow activation trigger.

    ``type`` is one of ``alert``, ``interval``, ``manual``, ``webhook``.
    ``with_`` holds type-specific parameters (e.g. ``cel`` expression for
    alert triggers, ``cron`` expression for interval triggers).
    """

    type: str
    with_: dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """Top-level declarative workflow definition mapped from YAML."""

    id: str
    description: str = ""
    triggers: list[Trigger] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)

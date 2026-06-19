"""YAML → Workflow loader.

Usage::

    from shared.workflows.loader import load_yaml, load_file, load_all

    wf = load_yaml(yaml_str)
    workflows = load_all(["playbooks/*.yaml", "custom/*.yaml"])
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from shared.workflows.models import Action, Step, Trigger, Workflow

__all__ = ["load_yaml", "load_file", "load_all"]


def _parse_action(raw: dict) -> Action:
    return Action(type=raw["type"], with_=raw.get("with", {}))


def _parse_step(raw: dict) -> Step:
    return Step(
        name=raw["name"],
        provider=raw.get("provider"),
        if_=raw.get("if"),
        actions=[_parse_action(a) for a in raw.get("actions", [])],
    )


def _parse_trigger(raw: dict) -> Trigger:
    return Trigger(type=raw["type"], with_=raw.get("with", {}))


def _parse_workflow(raw: dict) -> Workflow:
    return Workflow(
        id=raw["id"],
        description=raw.get("description", ""),
        triggers=[_parse_trigger(t) for t in raw.get("triggers", [])],
        steps=[_parse_step(s) for s in raw.get("steps", [])],
    )


def load_yaml(data: str) -> Workflow:
    """Parse a YAML string into a ``Workflow``."""
    raw = yaml.safe_load(data)
    if not isinstance(raw, dict):
        raise ValueError("YAML root must be a mapping")
    return _parse_workflow(raw)


def load_file(path: str | Path) -> Workflow:
    """Load a single workflow YAML file."""
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError("YAML root must be a mapping")
    return _parse_workflow(raw)


def _load_all_from_path(pattern: str) -> list[Workflow]:
    """Load all workflow YAML files matching a glob pattern."""
    workflows: list[Workflow] = []
    for p in sorted(Path().glob(pattern)):
        if p.suffix in (".yaml", ".yml"):
            workflows.append(load_file(p))
    return workflows


def load_all(patterns: list[str] | None = None) -> list[Workflow]:
    """Load workflows from one or more glob patterns.

    Defaults to ``["workflows/*.yaml", "workflows/*.yml"]``.
    """
    if patterns is None:
        patterns = ["workflows/*.yaml", "workflows/*.yml"]

    workflows: list[Workflow] = []
    seen: set[str] = set()
    for pattern in patterns:
        for p in sorted(Path().glob(pattern)):
            if p.suffix not in (".yaml", ".yml"):
                continue
            if p.name in seen:
                continue
            seen.add(p.name)
            workflows.append(load_file(p))
    return workflows

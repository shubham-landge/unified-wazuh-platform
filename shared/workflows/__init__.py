"""Declarative YAML workflow engine — replaces hardcoded SOAR playbooks."""

from shared.workflows.context import WorkflowContext, interpolate
from shared.workflows.engine import WorkflowEngine
from shared.workflows.loader import load_all, load_file, load_yaml
from shared.workflows.models import Action, Step, Trigger, Workflow
from shared.workflows.triggers import match_trigger

__all__ = [
    "Action",
    "Step",
    "Trigger",
    "Workflow",
    "WorkflowContext",
    "WorkflowEngine",
    "interpolate",
    "load_all",
    "load_file",
    "load_yaml",
    "match_trigger",
]

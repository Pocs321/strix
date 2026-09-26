"""Strix 2 extension bootstrap.

One place to wire Strix 2's additive capabilities into a run without scattering
edits through the upstream startup path. Called once at the top of
``run_strix_scan`` (the single upstream edit); everything else it touches is a
new module. Idempotent — safe to call again on resume or in tests.

Currently registers the two-tier finding model's candidate tools and binds the
candidate store to the run directory. Future phases add domain tools (network/
cloud) and skill directories here through the same seams
(``register_agent_tools`` / ``register_skill_dir``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from strix.agents.factory import register_agent_tools
from strix.candidates.store import reset_candidate_store
from strix.tools.candidates.tools import (
    create_candidate,
    dismiss_candidate,
    list_candidates,
    promote_candidate,
)


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_CANDIDATE_TOOLS = (create_candidate, list_candidates, promote_candidate, dismiss_candidate)


def install_strix2_extensions(run_dir: Path | None = None) -> None:
    """Register Strix 2 tools and bind per-run stores. Idempotent."""
    reset_candidate_store(run_dir)
    register_agent_tools(*_CANDIDATE_TOOLS)
    logger.info("Strix 2 extensions installed (candidate tools registered, run_dir=%s)", run_dir)

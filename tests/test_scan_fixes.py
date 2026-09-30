"""Exercise live-scan worktree isolation with native tools and scripted inference."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from agents import RunConfig
from agents.sandbox import SandboxRunConfig

from strix.core.agents import AgentCoordinator
from strix.core.hooks import ReportUsageHooks
from strix.fix import FindingContext
from strix.fix import runtime as fix_runtime
from strix.fix.scan import ScanFixes
from strix.fix.session import WorktreeSession
from tests.test_fix_completion import ScriptedModel, finish, patch, suite_commands
from tests.test_fix_reliability import LocalSandbox, existing_suite
from tests.test_fix_runtime import _git, _request, _workspace


def setup(tmp_path):
    source, _ = _workspace(tmp_path)
    commit = existing_suite(source)
    parent = LocalSandbox(tmp_path / "sandbox")
    coordinator = AgentCoordinator()
    fixes = ScanFixes(
        session=parent,
        coordinator=coordinator,
        parent_id="root",
        scan_id="scan",
        state_dir=tmp_path / "state",
        local_sources=[{"source_path": str(source)}],
        hooks=ReportUsageHooks(model="test", max_turns=1000),
    )
    fixes.base = str(tmp_path / "sandbox" / "fixes")
    candidate = _request(commit).candidate
    candidate.finding = FindingContext(validation_status="confirmed", title="Unsafe result")
    report = {
        "id": "finding",
        "validation_status": "confirmed",
        "fix_candidate": candidate.model_dump(mode="json"),
    }
    return fixes, report, source, parent


@pytest.mark.asyncio
async def test_parallel_fixes_use_worktrees_without_modifying_scan_source(tmp_path, monkeypatch):
    fixes, report, source, parent = setup(tmp_path)
    models = {}

    def config(env):
        model = models.setdefault(
            env.execution_id, ScriptedModel([*patch(), *suite_commands(), finish("done")])
        )
        return RunConfig(
            model=model, sandbox=SandboxRunConfig(session=env.session), tracing_disabled=True
        )

    monkeypatch.setattr(fix_runtime, "_run_config", config)
    fixes.notify(report)
    fixes.notify({**report, "id": "another-finding"})
    await fixes.wait()
    assert len(models) == 2
    assert all(record["status"] == "done" for record in fixes.records.values()), fixes.records
    assert all(Path(record["artifact"]).exists() for record in fixes.records.values())
    assert _git(source, "status", "--porcelain") == ""
    assert "unsafe" in (source / "app.py").read_text()
    assert parent.state.manifest.root == str(tmp_path / "sandbox")
    assert not list((tmp_path / "sandbox/fixes/worktrees").glob("*/app.py"))
    assert not list((tmp_path / "state/fixes").glob("*/source"))


@pytest.mark.asyncio
async def test_unconfirmed_duplicate_and_exhausted_findings_do_not_start_agent(tmp_path):
    fixes, report, _, _ = setup(tmp_path)
    fixes._run = AsyncMock()
    fixes.notify({**report, "validation_status": "unconfirmed"})
    await asyncio.sleep(0)
    fixes._run.assert_not_called()
    fixes.notify(report)
    fixes.notify(report)
    await fixes.wait()
    assert fixes._run.await_count == 1
    fixes.closed = False
    fixes.records["finding"]["turns"] = 300
    fixes.records["finding"]["status"] = "running"
    fixes.tasks.clear()
    fixes.notify(report)
    await fixes.wait()
    assert fixes._run.await_count == 1


@pytest.mark.asyncio
async def test_worktree_process_cleanup_never_terminates_parent_sessions(tmp_path):
    parent = LocalSandbox(tmp_path)
    parent.exec = AsyncMock()
    parent.pty_terminate_all = AsyncMock()
    child = WorktreeSession(parent, str(tmp_path / "fix"), "fix-one")
    await child.pty_terminate_all()
    parent.pty_terminate_all.assert_not_called()
    assert parent.exec.call_args.args[3] == "fix-one"
    with pytest.raises(ValueError, match="another agent"):
        await child.pty_write_stdin(session_id=123, chars="kill")

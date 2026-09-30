"""Fix delegation through the native create_agent tool, child loop and worktrees."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from agents import RunConfig
from agents.sandbox import SandboxRunConfig
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.core.execution import spawn_child_agent
from strix.core.hooks import ReportUsageHooks
from strix.fix import FindingContext
from strix.fix import scan as scan_module
from strix.fix.scan import ScanFixes
from strix.fix.session import WorktreeSession
from strix.report.state import ReportState
from strix.tools.agents_graph.tools import create_agent
from tests.test_fix_completion import ScriptedModel, finish, patch, suite_commands
from tests.test_fix_reliability import LocalSandbox, existing_suite
from tests.test_fix_runtime import _git, _request, _workspace


def setup(tmp_path):
    source, _ = _workspace(tmp_path)
    commit = existing_suite(source)
    parent = LocalSandbox(tmp_path / "sandbox")
    coordinator = AgentCoordinator()
    candidate = _request(commit).candidate
    candidate.finding = FindingContext(validation_status="confirmed", title="Unsafe result")
    report = {
        "id": "finding",
        "validation_status": "confirmed",
        "fix_candidate": candidate.model_dump(mode="json"),
    }
    reports = [report]
    fixes = ScanFixes(
        session=parent,
        coordinator=coordinator,
        scan_id="scan",
        state_dir=tmp_path / "state",
        local_sources=[{"source_path": str(source)}],
        hooks=ReportUsageHooks(model="test", max_turns=1000),
        report_state=SimpleNamespace(get_existing_vulnerabilities=lambda: reports),
    )
    fixes.base = str(tmp_path / "sandbox" / "fixes")
    sessions = []

    async def native(**kwargs):
        return await spawn_child_agent(
            coordinator=coordinator,
            agents_db_path=tmp_path / "agents.db",
            sessions_to_close=sessions,
            interactive=False,
            **kwargs,
        )

    async def spawn(**kwargs):
        finding_id = kwargs.pop("fix_finding_id")
        return await fixes.spawn(finding_id, native, **kwargs)

    context = ToolContext(
        tool_name="create_agent",
        tool_call_id="spawn-test",
        tool_arguments="{}",
        context={
            "coordinator": coordinator,
            "agent_id": "reporter",
            "parent_id": "root",
            "spawn_child_agent": spawn,
        },
    )
    return fixes, report, source, parent, reports, context, sessions


async def delegate(context, finding_id="finding"):
    return json.loads(
        await create_agent.on_invoke_tool(
            context,
            json.dumps(
                {
                    "name": "Fix agent",
                    "task": "Fix the saved issue and run regression and customer tests.",
                    "skills": [],
                    "inherit_context": False,
                    "fix_finding_id": finding_id,
                }
            ),
        )
    )


@pytest.mark.asyncio
async def test_native_parallel_fixes_deliver_patches_and_preserve_scan_source(
    tmp_path, monkeypatch
):
    fixes, report, source, parent, reports, context, sessions = setup(tmp_path)
    models, stages = {}, []
    reports.append({**report, "id": "another-finding"})

    def config(env):
        model = models.setdefault(
            env.execution_id, ScriptedModel([*patch(), *suite_commands(), finish("done")])
        )
        return RunConfig(
            model=model, sandbox=SandboxRunConfig(session=env.session), tracing_disabled=True
        )

    async def sink(stage, report, result, artifact):
        stages.append((stage, report["id"], result, artifact))
        return True

    monkeypatch.setattr(scan_module, "_run_config", config)
    fixes.sink = sink
    first, second = await asyncio.gather(delegate(context), delegate(context, "another-finding"))
    assert first["success"] and second["success"], (first, second)
    duplicate = await delegate(context)
    assert duplicate["agent_id"] == first["agent_id"]
    await fixes.wait()
    assert len(models) == 2
    assert all(record["status"] == "done" for record in fixes.records.values()), fixes.records
    assert all(Path(record["artifact"]).exists() for record in fixes.records.values())
    assert all(
        fixes.coordinator.parent_of[result["agent_id"]] == "reporter" for result in [first, second]
    )
    assert len([s for s in stages if s[0] == "finished" and s[2].state == "ready"]) == 2
    assert _git(source, "status", "--porcelain") == ""
    assert "unsafe" in (source / "app.py").read_text()
    assert parent.state.manifest.root == str(tmp_path / "sandbox")
    assert not list((tmp_path / "sandbox/fixes/worktrees").glob("*/app.py"))
    assert not list((tmp_path / "state/fixes").glob("*/source"))
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_delegation_errors_reach_reporting_agent_before_any_model_call(tmp_path):
    fixes, report, _, _, _, context, _ = setup(tmp_path)
    missing = await delegate(context, "unknown")
    assert not missing["success"] and "Save the vulnerability" in missing["error"]
    report["validation_status"] = "unconfirmed"
    assert "confirmed" in (await delegate(context))["error"]
    report["validation_status"] = "confirmed"
    fixes.records["finding"] = {"turns": 300}
    assert "300-turn" in (await delegate(context))["error"]
    fixes.records.clear()
    fixes.sink = AsyncMock(side_effect=RuntimeError("Missing callback configuration"))
    result = await delegate(context)
    assert not result["success"] and "Missing callback configuration" in result["error"]
    assert not fixes.tasks


@pytest.mark.asyncio
async def test_blocked_native_child_has_no_patch(tmp_path, monkeypatch):
    fixes, _, _, _, _, context, sessions = setup(tmp_path)
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([*patch(), finish("blocked")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    assert (await delegate(context))["success"]
    await fixes.wait()
    assert fixes.records["finding"]["status"] == "stopped"
    assert not list((tmp_path / "state/fixes").glob("*/prepared-fix.zip"))
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_finding_revision_invalidates_active_completion(tmp_path):
    fixes, report, _, _, _, _, _ = setup(tmp_path)
    digest = fixes._finding("finding")[1].digest()
    assert fixes._current("finding", digest)
    report["fix_candidate"]["security_invariant"] = "Revised attack"
    assert not fixes._current("finding", digest)
    fixes.report_state.get_existing_vulnerabilities().clear()
    assert not fixes._current("finding", digest)


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


@pytest.mark.asyncio
async def test_native_child_keeps_cumulative_turn_cap_and_does_not_export_partial_patch(
    tmp_path, monkeypatch
):
    fixes, _, _, _, _, context, sessions = setup(tmp_path)
    fixes.records["finding"] = {"digest": "older-candidate", "turns": 299, "status": "done"}
    model = ScriptedModel([*patch(), finish("done")])
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=model,
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    assert (await delegate(context))["success"]
    await fixes.wait()
    assert fixes.records["finding"]["turns"] == 300
    assert fixes.records["finding"]["status"] == "stopped"
    assert not list((tmp_path / "state/fixes").glob("*/prepared-fix.zip"))
    for session in sessions:
        session.close()


@pytest.mark.asyncio
async def test_saving_report_does_not_launch_until_reporting_agent_delegates(tmp_path, monkeypatch):
    fixes, report, _, _, _, context, sessions = setup(tmp_path)
    state = ReportState("native-handoff")
    state._run_dir = tmp_path / "report"
    fixes.report_state = state
    report_id = state.add_vulnerability_report(
        title="Unsafe result",
        severity="high",
        validation_status="confirmed",
        fix_candidate=report["fix_candidate"],
    )
    assert not fixes.tasks
    monkeypatch.setattr(
        scan_module,
        "_run_config",
        lambda env: RunConfig(
            model=ScriptedModel([finish("blocked")]),
            sandbox=SandboxRunConfig(session=env.session),
            tracing_disabled=True,
        ),
    )
    spawned = await delegate(context, report_id)
    assert spawned["success"], spawned
    await fixes.wait()
    assert fixes.coordinator.parent_of[spawned["agent_id"]] == "reporter"
    for session in sessions:
        session.close()

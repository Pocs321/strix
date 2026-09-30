"""Exercise the public OSS entry point with real tools and scripted inference."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import stat
import sys
import zipfile
from pathlib import Path

import pytest
from agents import RunConfig
from agents.sandbox import SandboxRunConfig

from strix.fix import FixPreparationRequestV1
from strix.fix import runtime as fix_runtime
from strix.interface import fix_cli
from tests.test_fix_completion import ScriptedModel, finish, patch, shell, suite_commands
from tests.test_fix_reliability import LocalSandbox, existing_suite
from tests.test_fix_runtime import _git, _request, _workspace


def _local_runtime(monkeypatch, tmp_path, model):
    root = tmp_path / "execution" / "source"
    original_environment = fix_runtime._RuntimeEnvironment
    model.root = str(root)

    async def sandbox(_sandbox_id):
        return LocalSandbox(root.parent)

    async def noop(*_args):
        pass

    monkeypatch.setattr(fix_cli, "_preflight", noop)
    monkeypatch.setattr(fix_runtime, "_create_command_sandbox", sandbox)
    monkeypatch.setattr(fix_runtime.session_manager, "cleanup", noop)
    monkeypatch.setattr(
        fix_runtime,
        "_RuntimeEnvironment",
        lambda **kwargs: original_environment(**kwargs, sandbox_workspace=str(root)),
    )
    monkeypatch.setattr(
        fix_runtime,
        "_run_config",
        lambda env: RunConfig(
            model=model, sandbox=SandboxRunConfig(session=env.session), tracing_disabled=True
        ),
    )


@pytest.mark.parametrize("blocked", [False, True])
def test_cli_runs_shared_workflow_and_preserves_original_checkout(tmp_path, monkeypatch, blocked):
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    request = _request(commit)
    finding = {"id": "vuln-1", "fix_candidate": request.candidate.model_dump(mode="json")}
    findings_path = tmp_path / "vulnerabilities.json"
    findings_path.write_text(json.dumps([finding]))
    review = (
        [shell("exit 1"), finish("blocked", "Required tests need a customer database.")]
        if blocked
        else [*suite_commands(), finish("approved", "Existing and regression tests passed.")]
    )
    model = ScriptedModel([*patch(), finish("done")], review)
    _local_runtime(monkeypatch, tmp_path, model)
    output = tmp_path / "result.json"

    code = fix_cli.run_fix(
        [
            "--finding",
            str(findings_path),
            "--finding-id",
            "vuln-1",
            "--repo",
            str(workspace),
            "--output",
            str(output),
        ]
    )

    assert code == (2 if blocked else 0)
    result = json.loads(output.read_text())
    assert result["state"] == ("blocked" if blocked else "ready")
    assert result["changed_files"]
    assert "safe" in output.with_suffix(".patch").read_text()
    assert ("customer database" if blocked else "tests passed") in output.with_suffix(
        ".md"
    ).read_text()
    with zipfile.ZipFile(output.with_suffix(".zip")) as artifact:
        assert "files/tests/test_security.py" in artifact.namelist()
        assert "tool-results.jsonl" in artifact.namelist()
    assert _git(workspace, "status", "--porcelain") == ""
    assert _git(workspace, "rev-parse", "HEAD") == commit
    assert "unsafe" in (workspace / "app.py").read_text()
    assert not (workspace / "tests/test_security.py").exists()


def test_stale_request_delivers_explanation_without_running_agents(tmp_path, monkeypatch):
    workspace, _ = _workspace(tmp_path)
    request = _request("a" * 40)
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json())
    model = ScriptedModel([], [])
    _local_runtime(monkeypatch, tmp_path, model)
    output = tmp_path / "result.json"

    assert (
        fix_cli.run_fix(
            [
                "--request",
                str(request_path),
                "--repo",
                str(workspace),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert json.loads(output.read_text())["state"] == "stale"
    assert not model.inputs["repair"]
    assert output.with_suffix(".patch").read_text() == ""


def test_dirty_checkout_is_preserved_and_never_sent_to_agents(tmp_path, monkeypatch):
    workspace, commit = _workspace(tmp_path)
    (workspace / "app.py").write_text("user work in progress")
    request_path = tmp_path / "request.json"
    request_path.write_text(_request(commit).model_dump_json())
    model = ScriptedModel([], [])
    _local_runtime(monkeypatch, tmp_path, model)

    assert (
        fix_cli.run_fix(
            [
                "--request",
                str(request_path),
                "--repo",
                str(workspace),
                "--output",
                str(tmp_path / "result.json"),
            ]
        )
        == 1
    )
    assert (workspace / "app.py").read_text() == "user work in progress"
    assert not model.inputs["repair"]


@pytest.mark.asyncio
async def test_interruption_exports_partial_work_before_removing_temporary_clone(
    tmp_path, monkeypatch
):
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    waiting = asyncio.Event()

    class PausedModel(ScriptedModel):
        async def get_response(self, **kwargs):
            if not self.responses["repair"]:
                waiting.set()
                await asyncio.Event().wait()
            return await super().get_response(**kwargs)

    model = PausedModel(patch(), [])
    _local_runtime(monkeypatch, tmp_path, model)
    output = tmp_path / "partial.zip"
    task = asyncio.create_task(
        fix_runtime.run_isolated_fix_preparation(
            _request(commit),
            workspace,
            artifact_path=output,
        )
    )
    try:
        await asyncio.wait_for(waiting.wait(), timeout=10)
    finally:
        task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with zipfile.ZipFile(output) as artifact:
        assert b"return 'safe'" in artifact.read("files/app.py")
    assert _git(workspace, "status", "--porcelain") == ""


def test_finding_selection_is_required_before_preflight(tmp_path, monkeypatch):
    path = tmp_path / "findings.json"
    path.write_text('[{"id": "one"}, {"id": "two"}]')
    monkeypatch.setattr(fix_cli, "_preflight", lambda: pytest.fail("must not start execution"))
    assert fix_cli.run_fix(["--finding", str(path), "--repo", str(tmp_path)]) == 1


def test_fix_help_is_dispatched_without_scan_setup(monkeypatch, capsys):
    main = importlib.import_module("strix.interface.main")

    monkeypatch.setattr(sys, "argv", ["strix", "fix", "--help"])
    monkeypatch.setattr(main, "parse_arguments", lambda: pytest.fail("scan parser must not run"))
    with pytest.raises(SystemExit, match="0"):
        main.main()
    assert "--finding" in capsys.readouterr().out


def test_legacy_empty_credential_field_is_accepted_but_forwarding_is_rejected():
    request = _request("a" * 40).model_dump()
    assert "credentials_allowed" not in request
    FixPreparationRequestV1.model_validate({**request, "credentials_allowed": []})
    with pytest.raises(ValueError, match="credentials_allowed"):
        FixPreparationRequestV1.model_validate({**request, "credentials_allowed": ["ANY_HOST_KEY"]})


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_cli_outputs_and_in_progress_archive_are_private_in_shared_directory(tmp_path, monkeypatch):
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    request_path = tmp_path / "request.json"
    request_path.write_text(_request(commit).model_dump_json())
    shared = tmp_path / "shared-output"
    shared.mkdir()
    shared.chmod(0o777)
    output = shared / "result.json"
    model = ScriptedModel([*patch(), finish("done")], [*suite_commands(), finish("approved")])
    _local_runtime(monkeypatch, tmp_path, model)
    original_writestr = zipfile.ZipFile.writestr
    writes_checked = []

    def private_writestr(archive, name, data, *args, **kwargs):
        # Check the open archive before source/log bytes enter it, not just after close.
        assert stat.S_IMODE(os.fstat(archive.fp.fileno()).st_mode) == 0o600
        writes_checked.append(name)
        return original_writestr(archive, name, data, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "writestr", private_writestr)
    previous = os.umask(0)
    try:
        assert (
            fix_cli.run_fix(
                [
                    "--request",
                    str(request_path),
                    "--repo",
                    str(workspace),
                    "--output",
                    str(output),
                ]
            )
            == 0
        )
    finally:
        os.umask(previous)
    assert "changes.patch" in writes_checked
    assert "agent-sessions.json" in writes_checked
    assert stat.S_IMODE(shared.stat().st_mode) == 0o777
    assert {p.name for p in shared.iterdir()} == {
        "result.json",
        "result.md",
        "result.patch",
        "result.zip",
    }
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in shared.iterdir())


def test_default_outputs_allow_repeated_runs_from_inside_the_repository(tmp_path, monkeypatch):
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    request_path = tmp_path / "request.json"
    request_path.write_text(_request(commit).model_dump_json())
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.chdir(workspace)

    for attempt in range(2):
        model = ScriptedModel([*patch(), finish("done")], [*suite_commands(), finish("approved")])
        with monkeypatch.context() as runtime_patch:
            _local_runtime(runtime_patch, tmp_path / f"attempt-{attempt}", model)
            assert fix_cli.run_fix(["--request", str(request_path), "--repo", "."]) == 0
        assert _git(workspace, "status", "--porcelain") == ""

    assert len(list((home / ".strix/fixes").glob("fix-*/result.json"))) == 2
    assert not (workspace / "strix_runs").exists()


def test_default_output_cannot_resolve_inside_source_checkout(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    with pytest.raises(ValueError, match="set --output outside"):
        fix_cli._default_output(tmp_path)
    assert not (tmp_path / ".strix").exists()

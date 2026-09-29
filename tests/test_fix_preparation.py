"""Tests for fix candidate anchoring and repository preparation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from strix.fix.contracts import (
    BlockerKind,
    CandidateLocation,
    CheckResult,
    CheckStatus,
    CommandSpec,
    FixCandidateV1,
    FixEdit,
    FixPreparationRequestV1,
    PreparationState,
    RegressionTestResult,
    RepairOutcome,
    RepairStatus,
    ReproductionSpec,
    SourceIdentity,
    SourceIdentityKind,
    VerificationDecision,
    VerificationTarget,
    VerifierResult,
    candidate_from_legacy_report,
)
from strix.fix.evidence import command_status, passed_test_count, record_test_execution
from strix.fix.locations import AnchorStatus, anchor_location
from strix.fix.prepare import (
    PreparationContext,
    PreparationPolicy,
    _network_isolation_prefix,
    _workspace_digest,
    build_git_manifest,
    build_git_patch,
    prepare_fix,
    run_command,
)


if TYPE_CHECKING:
    from pathlib import Path


def _regression() -> RegressionTestResult:
    base = CheckResult(
        name="authorization",
        argv=["python", "regression.py"],
        status=CheckStatus.FAILED,
        exit_code=1,
        duration_seconds=0,
        target=VerificationTarget.BASE,
        output="unauthorized access allowed",
    )
    passed = base.model_copy(
        update={
            "status": CheckStatus.PASSED,
            "exit_code": 0,
            "target": VerificationTarget.PATCHED,
            "output": "passed",
        }
    )
    return RegressionTestResult(
        name="authorization",
        expected_base_failure="unauthorized access allowed",
        harness_sha256="a" * 64,
        base=base,
        patched=passed,
        behavior=passed,
    )


def _git(workspace: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["/usr/bin/git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _workspace(tmp_path: Path) -> tuple[Path, str]:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    _git(workspace, "init")
    _git(workspace, "config", "user.email", "test@example.com")
    _git(workspace, "config", "user.name", "Test")
    (workspace / "app.py").write_text("def result():\n    return 'unsafe'\n", encoding="utf-8")
    (workspace / "test_existing.py").write_text(
        "import unittest\nfrom app import result\nclass Existing(unittest.TestCase):\n"
        "    def test_result_type(self): self.assertIsInstance(result(), str)\n"
    )
    _git(workspace, "add", "app.py", "test_existing.py")
    _git(workspace, "commit", "-m", "initial")
    return workspace, _git(workspace, "rev-parse", "HEAD")


def _candidate(
    commit: str,
    *,
    reproduction: ReproductionSpec | None = None,
) -> FixCandidateV1:
    if reproduction is None:
        reproduction = ReproductionSpec(
            instructions="Confirm that result returns safe.",
            command=CommandSpec(
                name="security reproduction",
                argv=[
                    sys.executable,
                    "-c",
                    "from app import result; assert result() == 'safe'",
                ],
            ),
        )
    return FixCandidateV1(
        source_identity=SourceIdentity(kind=SourceIdentityKind.COMMIT, value=commit),
        security_invariant="Return a safe value.",
        finding_locations=[
            CandidateLocation(
                file="app.py",
                start_line=1,
                end_line=2,
                snippet="def result():\n    return 'unsafe'",
            )
        ],
        draft_edits=[
            FixEdit(
                file="app.py",
                start_line=2,
                end_line=2,
                before="    return 'unsafe'",
                after="    return 'safe'",
            )
        ],
        reproduction=reproduction,
    )


def _request(candidate: FixCandidateV1, *, attempts: int = 2) -> FixPreparationRequestV1:
    return FixPreparationRequestV1(
        scan_id="scan-1",
        finding_id="finding-1",
        candidate=candidate,
        checks=[
            CommandSpec(
                name="compile",
                argv=[
                    sys.executable,
                    "-c",
                    "compile(open('app.py', encoding='utf-8').read(), 'app.py', 'exec')",
                ],
            )
        ],
        max_repair_attempts=attempts,
        max_agent_turns=8,
        network_allowed=True,
    )


async def _noop_repair(
    context: PreparationContext,
    _checks: list[CheckResult],
) -> RepairOutcome:
    path = context.workspace / "app.py"
    if path.exists():
        path.write_text(
            path.read_text(encoding="utf-8").replace("'unsafe'", "'safe'"),
            encoding="utf-8",
        )
    (context.workspace / "test_app.py").write_text(
        "import unittest\nfrom app import result\nclass SecurityTest(unittest.TestCase):\n"
        "    def test_safe(self): self.assertEqual(result(), 'safe')\n"
    )
    commands = [
        CommandSpec(
            name="regression",
            argv=[sys.executable, "-m", "unittest", "test_app"],
            purpose="regression",
        ),
        CommandSpec(
            name="existing suite",
            argv=[sys.executable, "-m", "unittest", "test_existing"],
            purpose="unit",
        ),
        *context.request.checks,
    ]
    digest = await _workspace_digest(context.workspace)
    results = []
    for command in commands:
        result = record_test_execution(
            await run_command(context.workspace, command, network_allowed=True), command
        )
        results.append(
            result.model_copy(update={"source_digest": digest, "environment_id": "test"})
        )
    return RepairOutcome(
        status=RepairStatus.COMPLETE,
        summary="Fixed and tested.",
        command_results=results,
        source_digest=digest,
        turns_used=1,
    )


async def _verified(
    _context: PreparationContext,
    _checks: list[CheckResult],
) -> VerifierResult:
    return VerifierResult(
        decision=VerificationDecision.VERIFIED,
        source_digest=_context.feedback[-1].repair.source_digest,
        summary="The invariant is closed.",
        security_invariant_closed=True,
        review_basis="code_review",
        regression_test_valid=True,
        unit_test_coverage_valid=True,
        reproduction_executed=False,
        reproduction_summary="The vulnerable input is rejected.",
        sibling_paths_reviewed=["app.py"],
        preserved_behaviors=["The module compiles."],
        regression_tests=[_regression()],
        security_tests=[
            CheckResult(
                name="security reproduction",
                argv=[sys.executable, "-c", "assert True"],
                status=CheckStatus.PASSED,
                exit_code=0,
                duration_seconds=0,
                target=VerificationTarget.PATCHED,
            )
        ],
    )


def test_candidate_from_legacy_report_preserves_draft_and_checks() -> None:
    candidate = candidate_from_legacy_report(
        {
            "remediation_steps": "Reject unsafe input.",
            "poc_description": "Call the vulnerable function.",
            "fix_verification": "Reasoned about the patched branch.",
            "code_locations": [
                {
                    "file": "src/app.py",
                    "start_line": 9,
                    "end_line": 9,
                    "snippet": "sink(value)",
                    "fix_before": "sink(value)",
                    "fix_after": "sink(clean(value))",
                }
            ],
        }
    )

    assert candidate is not None
    assert candidate.security_invariant == "Reject unsafe input."
    assert candidate.draft_edits[0].after == "sink(clean(value))"
    assert candidate.reported_checks[0].executed is False
    assert candidate.known_gaps == ["The reporting-agent verification is not independent."]


def test_anchor_location_rewrites_invented_line_numbers(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("first\nsecond\ntarget\nlast\n", encoding="utf-8")
    location = CandidateLocation(
        file="app.py",
        start_line=99,
        end_line=99,
        snippet="target",
    )

    result = anchor_location(tmp_path, location)

    assert result.status is AnchorStatus.UNIQUE
    assert result.location.start_line == 3
    assert result.location.end_line == 3


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("first\nlast\n", AnchorStatus.MISSING),
        ("target\nmiddle\ntarget\n", AnchorStatus.AMBIGUOUS),
    ],
)
def test_anchor_location_rejects_non_unique_source(
    tmp_path: Path,
    content: str,
    expected: AnchorStatus,
) -> None:
    (tmp_path / "app.py").write_text(content, encoding="utf-8")
    edit = FixEdit(
        file="app.py",
        start_line=1,
        end_line=1,
        before="target",
        after="safe",
    )

    assert anchor_location(tmp_path, edit).status is expected


def test_anchor_location_detects_stale_file_digest(tmp_path: Path) -> None:
    original = "target\n"
    (tmp_path / "app.py").write_text("changed\n", encoding="utf-8")
    edit = FixEdit(
        file="app.py",
        start_line=1,
        end_line=1,
        before="target",
        after="safe",
        original_sha256=hashlib.sha256(original.encode()).hexdigest(),
    )

    assert anchor_location(tmp_path, edit).status is AnchorStatus.STALE


@pytest.mark.asyncio
async def test_prepare_fix_rejects_wrong_source_commit(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)

    result = await prepare_fix(
        _request(_candidate("0" * 40)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.STALE
    assert result.blocker is not None
    assert result.blocker.kind is BlockerKind.SOURCE


@pytest.mark.asyncio
async def test_prepare_fix_rejects_dirty_workspace(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    (workspace / "stray.txt").write_text("unrelated\n", encoding="utf-8")

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.STALE


@pytest.mark.asyncio
async def test_build_git_manifest_lists_files_inside_new_directory(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)
    package = workspace / "pkg"
    package.mkdir()
    (package / "mod.py").write_text("x = 1\n", encoding="utf-8")

    entries, _summary, _artifact = await build_git_manifest(workspace)

    paths = {entry.path for entry in entries}
    assert "pkg/mod.py" in paths
    entry = next(entry for entry in entries if entry.path == "pkg/mod.py")
    assert entry.operation == "add"
    assert entry.resulting_sha256 is not None


@pytest.mark.asyncio
async def test_run_command_drops_ambient_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_AMBIENT_TOKEN", "hunter2")
    command = CommandSpec(
        name="env probe",
        argv=[
            sys.executable,
            "-c",
            "import os; print(os.environ.get('STRIX_AMBIENT_TOKEN', '<absent>'))",
        ],
    )

    sealed = await run_command(tmp_path, command, network_allowed=True)
    assert sealed.status is CheckStatus.PASSED
    assert "<absent>" in sealed.output

    granted = await run_command(
        tmp_path,
        command,
        credentials_allowed=["STRIX_AMBIENT_TOKEN"],
        network_allowed=True,
    )
    assert granted.status is CheckStatus.PASSED
    assert "hunter2" in granted.output


@pytest.mark.asyncio
async def test_run_command_blocks_egress_when_network_not_allowed(tmp_path: Path) -> None:
    command = CommandSpec(
        name="egress probe",
        argv=[
            sys.executable,
            "-c",
            (
                "import socket, sys; s = socket.socket(); s.settimeout(3); "
                "sys.exit(0 if s.connect_ex(('1.1.1.1', 53)) == 0 else 1)"
            ),
        ],
    )

    result = await run_command(tmp_path, command)

    if _network_isolation_prefix() is None:
        assert result.status is CheckStatus.UNAVAILABLE
        assert "not run" in result.output
    else:
        assert result.status is CheckStatus.FAILED


@pytest.mark.asyncio
async def test_manifest_patch_includes_untracked_companion_file(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    (workspace / "companion.py").write_text("guard = True\n")
    manifest, _, _ = await build_git_manifest(workspace)
    patch = await build_git_patch(workspace, manifest)
    assert b"b/companion.py" in patch
    assert b"+guard = True" in patch
    _git(workspace, "diff", "--check")


def test_skipped_check_and_missing_runtime_are_not_passing_evidence() -> None:
    assert command_status(0, "Skipping to avoid parser lock")[0] is CheckStatus.SKIPPED
    assert command_status(127, "bun: command not found")[0] is CheckStatus.UNAVAILABLE
    assert (
        not _regression()
        .model_copy(
            update={"base": _regression().base.model_copy(update={"failure_kind": "environment"})}
        )
        .passed()
    )


def test_candidate_keeps_full_finding_without_inventing_reproduction() -> None:
    candidate = candidate_from_legacy_report(
        {
            "title": "Authorization bypass",
            "technical_analysis": "Critical exploit context.",
            "remediation_steps": "Enforce authorization.",
            "code_locations": [
                {
                    "file": "app.py",
                    "start_line": 1,
                    "end_line": 1,
                    "fix_before": "unsafe",
                    "fix_after": "safe",
                }
            ],
        }
    )
    assert candidate and candidate.finding
    assert candidate.finding.description == "Critical exploit context."
    assert candidate.reproduction is None


def test_ambiguous_imports_and_syntax_never_authorize_environment_recovery() -> None:
    for output in [
        "Cannot find module '/tmp/test/skills/policy.js'",
        "No module named 'wrong_repo_path'",
        "SyntaxError: invalid syntax",
    ]:
        status, kind = command_status(1, output)
        assert status is CheckStatus.FAILED
        assert kind == "unknown"
    assert command_status(127, "bun: command not found") == (CheckStatus.UNAVAILABLE, "environment")


def test_regression_requires_consistent_execution_provenance() -> None:
    regression = _regression()
    for leg in (regression.base, regression.patched, regression.behavior):
        leg.source_digest = "a" * 64
        leg.environment_id = "execution:0"
    assert regression.passed()
    regression.base.environment_id = "execution:1"
    assert not regression.passed()
    regression.base.environment_id = "execution:0"
    regression.behavior = regression.behavior.model_copy(update={"source_digest": "b" * 64})
    assert not regression.passed()


@pytest.mark.asyncio
async def test_agent_tests_are_reused_without_controller_execution(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    outcome = None

    async def repair(context, checks):
        nonlocal outcome
        outcome = await _noop_repair(context, checks)
        return outcome

    result = await prepare_fix(
        _request(_candidate(commit)), workspace, repair=repair, verify=_verified
    )
    assert result.state is PreparationState.READY
    assert result.validation_mode == "agent_review"
    assert result.test_plan is None
    assert result.checks == outcome.command_results
    assert result.checks[0].tests_passed == 1
    assert result.prepared_source_digest == result.verifier.source_digest


@pytest.mark.asyncio
async def test_review_can_request_more_than_two_repairs(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def review(context, checks):
        if context.attempt < 4:
            return VerifierResult(
                decision=VerificationDecision.REJECTED,
                summary="Inspect sibling path",
                gaps=["Inspect sibling path"],
            )
        assert context.feedback[-2].verifier.summary == "Inspect sibling path"
        return await _verified(context, checks)

    result = await prepare_fix(
        _request(_candidate(commit)), workspace, repair=_noop_repair, verify=review
    )
    assert result.state is PreparationState.READY
    assert len(result.attempt_history) == 4  # Legacy max_repair_attempts=2 is not a loop cap.


@pytest.mark.asyncio
@pytest.mark.parametrize("defect", ["missing_unit", "failed", "empty", "stale", "missing_request"])
async def test_agent_approval_owns_test_evidence_without_controller_retries(
    tmp_path: Path, defect: str
) -> None:
    workspace, commit = _workspace(tmp_path)

    async def repair(context, checks):
        result = await _noop_repair(context, checks)
        if defect == "missing_unit":
            result.command_results = [c for c in result.command_results if c.purpose != "unit"]
        elif defect == "missing_request":
            result.command_results = [c for c in result.command_results if c.purpose != "quality"]
        else:
            check = result.command_results[0]
            if defect == "failed":
                check.status, check.exit_code = CheckStatus.FAILED, 1
            elif defect == "empty":
                check.tests_passed = 0
            else:
                check.source_digest = "a" * 64
        return result

    request = _request(_candidate(commit))
    request.max_agent_turns = 2
    result = await prepare_fix(request, workspace, repair=repair, verify=_verified)
    # Deliberately scripted approval: test policy is the reviewer's responsibility.
    # This tests routing, not whether a real reviewer ought to approve this evidence.
    assert result.state is PreparationState.READY
    assert result.final_file_manifest
    assert result.attempts == 1
    assert not result.attempt_history[0].repair.gaps


@pytest.mark.asyncio
async def test_incomplete_validation_can_be_finished_by_reviewer(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    evidence = []

    async def repair(context, checks):
        result = await _noop_repair(context, checks)
        evidence.extend(result.command_results)
        evidence[1].status = CheckStatus.FAILED
        return result

    async def review(context, checks):
        assert checks[1].status is CheckStatus.FAILED
        command = CommandSpec(name="existing suite", argv=checks[1].argv, purpose="unit")
        executed = record_test_execution(
            await run_command(workspace, command, network_allowed=True), command
        )
        evidence[1] = executed.model_copy(
            update={"source_digest": evidence[0].source_digest, "environment_id": "test"}
        )
        return await _verified(context, checks)

    async def read_evidence():
        return list(evidence)

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=review,
        evidence_reader=read_evidence,
    )
    assert result.state is PreparationState.READY
    assert result.checks[1].status is CheckStatus.PASSED


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["budget", "blocked", "exception", "timeout", "cancel"])
async def test_interruptions_preserve_partial_patch_without_approval(
    tmp_path: Path, stop: str
) -> None:

    workspace, commit = _workspace(tmp_path)
    cancel = False

    async def repair(context, checks):
        nonlocal cancel
        result = await _noop_repair(context, checks)
        if stop == "budget":
            result.status = RepairStatus.BUDGET_EXHAUSTED
        elif stop == "blocked":
            result.status = RepairStatus.BLOCKED
        elif stop == "exception":
            raise RuntimeError("provider error")
        elif stop == "timeout":
            await asyncio.sleep(10)
        else:
            cancel = True
        return result

    async def review(*_args):
        raise AssertionError("Stopped repair must not be approved")

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=review,
        cancelled=lambda: cancel,
        policy=PreparationPolicy(timeout_seconds=1 if stop == "timeout" else 30),
    )
    assert result.state in {PreparationState.BLOCKED, PreparationState.FAILED}
    assert result.final_file_manifest


@pytest.mark.asyncio
async def test_review_mutation_blocks_delivery_without_controller_repair_loop(
    tmp_path: Path,
) -> None:
    workspace, commit = _workspace(tmp_path)

    async def review(context, checks):
        result = await _verified(context, checks)
        if context.attempt == 1:
            (workspace / "review.tmp").write_text("temporary")
        return result

    async def repair(context, checks):
        assert context.attempt == 1
        return await _noop_repair(context, checks)

    result = await prepare_fix(
        _request(_candidate(commit)), workspace, repair=repair, verify=review
    )
    assert result.state is PreparationState.BLOCKED
    assert "deliverable changed" in result.stop_reason
    assert result.attempts == 1
    assert result.final_file_manifest


@pytest.mark.asyncio
async def test_empty_deliverable_does_not_start_another_repair(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def repair(context, _checks):
        assert context.attempt == 1
        return RepairOutcome(status=RepairStatus.COMPLETE, summary="Done.")

    async def review(*_args):
        raise AssertionError("An empty artifact cannot be delivered")

    result = await prepare_fix(
        _request(_candidate(commit)), workspace, repair=repair, verify=review
    )
    assert result.state is PreparationState.BLOCKED
    assert result.attempts == 1
    assert "without a deliverable patch" in result.stop_reason


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Tests: 2 passed, 2 total", 2),
        ("2 pass\n0 fail", 2),
        ("# tests 2\n# pass 2\n# fail 0", 2),
        ("Ran 3 tests in 0.1s\n\nOK (skipped=1)", 2),
        ("3 examples, 0 failures, 1 pending", 2),
        ("--- PASS: TestSafe (0.00s)", 1),
        ("Ran 2 tests in 0.1s\n\nOK (skipped=2)", 0),
        ("No tests found", None),
    ],
)
def test_runner_summaries_record_actual_execution(output: str, expected: int | None) -> None:

    assert passed_test_count(output) == expected


def test_new_command_metadata_does_not_change_existing_finding_digest(tmp_path: Path) -> None:

    _root, commit = _workspace(tmp_path)
    candidate = _candidate(commit)
    payload = candidate.model_dump(mode="json")
    payload.pop("finding")
    payload["reproduction"]["command"].pop("purpose")
    previous = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert candidate.digest() == previous


def test_unknown_runner_format_preserves_exit_result_for_independent_review() -> None:

    command = CommandSpec(name="custom runner", argv=["./tests/run"], purpose="unit")
    result = record_test_execution(
        CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.PASSED,
            exit_code=0,
            duration_seconds=1,
            output="All project assertions completed successfully.",
        ),
        command,
    )
    assert result.status is CheckStatus.PASSED
    assert result.tests_passed is None

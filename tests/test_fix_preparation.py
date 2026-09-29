"""Tests for fix candidate anchoring and repository preparation."""

from __future__ import annotations

import hashlib
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
    FileManifestEntry,
    FixCandidateV1,
    FixEdit,
    FixPreparationRequestV1,
    PreparationBlocker,
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
from strix.fix.evidence import command_status
from strix.fix.locations import AnchorStatus, anchor_location
from strix.fix.prepare import (
    PreparationContext,
    _matches_baseline_failure,
    _network_isolation_prefix,
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
    _git(workspace, "add", "app.py")
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
    return RepairOutcome(
        status=RepairStatus.COMPLETE,
        summary="The repository fix is ready for independent evaluation.",
    )


async def _verified(
    _context: PreparationContext,
    _checks: list[CheckResult],
) -> VerifierResult:
    return VerifierResult(
        decision=VerificationDecision.VERIFIED,
        summary="The invariant is closed.",
        security_invariant_closed=True,
        reproduction_executed=True,
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
async def test_prepare_fix_returns_ready_with_manifest(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.READY
    assert result.attempts == 1
    assert [entry.path for entry in result.final_file_manifest] == ["app.py"]
    assert result.security_reproduction is not None
    assert result.security_reproduction.target is VerificationTarget.PATCHED


@pytest.mark.asyncio
async def test_prepare_fix_does_not_apply_draft_before_repair(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    observed_source: list[str] = []

    async def repair(
        context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        observed_source.append((context.workspace / "app.py").read_text(encoding="utf-8"))
        (context.workspace / "app.py").write_text(
            "def result():\n    return 'safe'\n",
            encoding="utf-8",
        )
        return RepairOutcome(
            status=RepairStatus.COMPLETE,
            summary="Implemented the repair from repository context.",
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=_verified,
    )

    assert result.state is PreparationState.READY
    assert observed_source == ["def result():\n    return 'unsafe'\n"]


@pytest.mark.asyncio
async def test_quality_gate_retries_once_before_verification(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    compile_calls = 0
    repair_calls = 0
    verification_calls = 0

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        nonlocal compile_calls
        compile_calls += 1
        failed = compile_calls == 1
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.FAILED if failed else CheckStatus.PASSED,
            exit_code=1 if failed else 0,
            duration_seconds=0,
            required=command.required,
        )

    async def repair(
        context: PreparationContext,
        checks: list[CheckResult],
    ) -> RepairOutcome:
        nonlocal repair_calls
        repair_calls += 1
        assert checks == [] if repair_calls == 1 else checks[0].status is CheckStatus.FAILED
        (context.workspace / "app.py").write_text(
            "def result():\n    return 'safe'\n",
            encoding="utf-8",
        )
        return RepairOutcome(status=RepairStatus.COMPLETE, summary="Repair complete.")

    async def verify(
        context: PreparationContext,
        checks: list[CheckResult],
    ) -> VerifierResult:
        nonlocal verification_calls
        verification_calls += 1
        return await _verified(context, checks)

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=verify,
        command_runner=runner,
    )

    assert result.state is PreparationState.READY
    assert repair_calls == 2
    assert compile_calls == 2
    assert verification_calls == 1


@pytest.mark.asyncio
async def test_failed_quality_gate_never_runs_security_verifier(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    verifier_called = False

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.FAILED,
            exit_code=1,
            duration_seconds=0,
            required=command.required,
        )

    async def verify(
        context: PreparationContext,
        checks: list[CheckResult],
    ) -> VerifierResult:
        nonlocal verifier_called
        verifier_called = True
        return await _verified(context, checks)

    result = await prepare_fix(
        _request(_candidate(commit), attempts=1),
        workspace,
        repair=_noop_repair,
        verify=verify,
        command_runner=runner,
    )

    assert result.state is PreparationState.FAILED
    assert verifier_called is False
    assert "quality gate" in result.stop_reason


@pytest.mark.asyncio
async def test_repository_baseline_failure_is_a_typed_blocker(
    tmp_path: Path,
) -> None:
    workspace, commit = _workspace(tmp_path)

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.FAILED,
            exit_code=1,
            duration_seconds=0,
            output="existing failure",
            required=command.required,
            baseline_status=CheckStatus.FAILED,
            baseline_exit_code=1,
            baseline_output="existing failure",
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
        command_runner=runner,
    )

    assert result.state is PreparationState.BLOCKED
    assert result.blocker is not None
    assert result.blocker.kind is BlockerKind.REPOSITORY_BASELINE
    assert result.attempts == 1


@pytest.mark.asyncio
async def test_different_candidate_and_baseline_failures_are_repairable(
    tmp_path: Path,
) -> None:
    workspace, commit = _workspace(tmp_path)
    repairs = 0

    async def repair(
        _context: PreparationContext,
        _feedback: list[CheckResult],
    ) -> RepairOutcome:
        nonlocal repairs
        repairs += 1
        return await _noop_repair(_context, _feedback)

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.FAILED,
            exit_code=1,
            duration_seconds=0,
            output="candidate-specific failure",
            required=command.required,
            baseline_status=CheckStatus.FAILED,
            baseline_exit_code=1,
            baseline_output="different pre-existing failure",
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=_verified,
        command_runner=runner,
    )

    assert result.state is PreparationState.FAILED
    assert result.blocker is None
    assert result.attempts == 2
    assert repairs == 2


@pytest.mark.asyncio
async def test_unavailable_required_check_is_a_typed_blocker(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.UNAVAILABLE,
            duration_seconds=0,
            output="compiler unavailable",
            required=command.required,
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=_verified,
        command_runner=runner,
    )

    assert result.state is PreparationState.BLOCKED
    assert result.blocker is not None
    assert result.blocker.kind is BlockerKind.ENVIRONMENT
    assert result.attempts == 1


@pytest.mark.asyncio
async def test_repairable_security_rejection_gets_one_retry(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    repair_feedback: list[list[str]] = []
    verifier_calls = 0

    async def repair(
        context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        repair_feedback.append(
            [
                gap
                for attempt in context.feedback
                if attempt.verifier is not None
                for gap in attempt.verifier.gaps
            ]
        )
        (context.workspace / "app.py").write_text(
            "def result():\n    return 'safe'\n",
            encoding="utf-8",
        )
        return RepairOutcome(status=RepairStatus.COMPLETE, summary="Repair complete.")

    async def verify(
        context: PreparationContext,
        checks: list[CheckResult],
    ) -> VerifierResult:
        nonlocal verifier_calls
        verifier_calls += 1
        if verifier_calls == 1:
            return VerifierResult(
                decision=VerificationDecision.REJECTED,
                summary="A sibling path remains vulnerable.",
                gaps=["Harden the sibling path."],
                repairable=True,
            )
        return await _verified(context, checks)

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=verify,
    )

    assert result.state is PreparationState.READY
    assert result.attempts == 2
    assert repair_feedback == [[], ["Harden the sibling path."]]


@pytest.mark.asyncio
async def test_security_blocker_stops_without_repair_retry(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    repair_calls = 0
    blocker = PreparationBlocker(
        kind=BlockerKind.EXTERNAL_CONFIGURATION,
        summary="A production account mapping is unavailable.",
        user_action="Provide the production account mapping.",
    )

    async def repair(
        context: PreparationContext,
        checks: list[CheckResult],
    ) -> RepairOutcome:
        nonlocal repair_calls
        repair_calls += 1
        return await _noop_repair(context, checks)

    async def verify(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> VerifierResult:
        return VerifierResult(
            decision=VerificationDecision.INCONCLUSIVE,
            summary=blocker.summary,
            blocker=blocker,
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=verify,
    )

    assert result.state is PreparationState.BLOCKED
    assert result.blocker == blocker
    assert repair_calls == 1


@pytest.mark.asyncio
async def test_budget_exhaustion_can_be_approved_by_independent_evidence(
    tmp_path: Path,
) -> None:
    workspace, commit = _workspace(tmp_path)
    verifier_called = False

    async def exhausted(
        context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        (context.workspace / "app.py").write_text(
            "def result():\n    return 'safe'\n",
            encoding="utf-8",
        )
        return RepairOutcome(
            status=RepairStatus.BUDGET_EXHAUSTED,
            summary="The repair hit its emergency turn ceiling after editing the patch.",
            turns_used=40,
        )

    async def verify(
        context: PreparationContext,
        checks: list[CheckResult],
    ) -> VerifierResult:
        nonlocal verifier_called
        verifier_called = True
        return await _verified(context, checks)

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=exhausted,
        verify=verify,
    )

    assert result.state is PreparationState.READY
    assert verifier_called is True
    assert result.attempt_history[0].repair.turns_used == 40
    assert result.changed_files == ["app.py"]


@pytest.mark.asyncio
async def test_budget_exhaustion_with_incomplete_evidence_is_blocked(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def exhausted(
        context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        (context.workspace / "app.py").write_text(
            "def result():\n    return 'safe'\n",
            encoding="utf-8",
        )
        return RepairOutcome(
            status=RepairStatus.BUDGET_EXHAUSTED,
            summary="The repair hit its emergency turn ceiling after editing the patch.",
            turns_used=40,
        )

    async def inconclusive(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> VerifierResult:
        return VerifierResult(
            decision=VerificationDecision.INCONCLUSIVE,
            summary="Production configuration could not be verified.",
            security_invariant_closed=False,
            gaps=["The production environment value is unavailable."],
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=exhausted,
        verify=inconclusive,
    )

    assert result.state is PreparationState.BLOCKED
    assert result.blocker is not None
    assert result.blocker.kind is BlockerKind.SECURITY_EVIDENCE
    assert result.attempt_history[0].repair.turns_used == 40


@pytest.mark.asyncio
async def test_prepare_fix_preserves_explicit_blocked_outcome(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)
    blocker = PreparationBlocker(
        kind=BlockerKind.CREDENTIAL,
        summary="A required credential is unavailable.",
        user_action="Provide a repository-scoped test credential.",
    )

    async def blocked(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        return RepairOutcome(
            status=RepairStatus.BLOCKED,
            summary=blocker.summary,
            blocker=blocker,
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=blocked,
        verify=_verified,
    )

    assert result.state is PreparationState.BLOCKED
    assert result.blocker == blocker
    assert result.verifier is None


@pytest.mark.asyncio
async def test_prepare_fix_requires_verifier_security_test(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def verify_without_test(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> VerifierResult:
        return VerifierResult(
            decision=VerificationDecision.VERIFIED,
            summary="The verifier did not execute the issue-specific test.",
            security_invariant_closed=True,
            reproduction_executed=False,
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=verify_without_test,
    )

    assert result.state is PreparationState.BLOCKED
    assert "paired functional regression" in " ".join(result.gaps)


@pytest.mark.asyncio
async def test_prepare_fix_requires_closed_security_invariant(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def incomplete(
        context: PreparationContext,
        checks: list[CheckResult],
    ) -> VerifierResult:
        verified = await _verified(context, checks)
        return verified.model_copy(update={"security_invariant_closed": False})

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=_noop_repair,
        verify=incomplete,
    )

    assert result.state is PreparationState.BLOCKED
    assert "invariant" in " ".join(result.gaps)


@pytest.mark.asyncio
async def test_prepare_fix_requires_a_source_change(tmp_path: Path) -> None:
    workspace, commit = _workspace(tmp_path)

    async def no_change(
        _context: PreparationContext,
        _checks: list[CheckResult],
    ) -> RepairOutcome:
        return RepairOutcome(status=RepairStatus.COMPLETE, summary="No change.")

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=no_change,
        verify=_verified,
    )

    assert result.state is PreparationState.FAILED
    assert result.final_file_manifest == []
    assert "change repository source" in result.stop_reason


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
async def test_prepare_fix_does_not_apply_escaping_draft_edit(tmp_path: Path) -> None:
    workspace, _commit = _workspace(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("target\n", encoding="utf-8")
    (workspace / "link.txt").symlink_to(outside)
    _git(workspace, "add", "link.txt")
    _git(workspace, "commit", "-m", "add link")
    candidate = _candidate(_git(workspace, "rev-parse", "HEAD")).model_copy(
        update={
            "draft_edits": [
                FixEdit(
                    file="link.txt",
                    start_line=1,
                    end_line=1,
                    before="target",
                    after="safe",
                )
            ]
        }
    )

    result = await prepare_fix(
        _request(candidate),
        workspace,
        repair=_noop_repair,
        verify=_verified,
    )

    assert result.state is PreparationState.READY
    assert outside.read_text(encoding="utf-8") == "target\n"
    assert "link.txt" not in result.changed_files


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


def test_baseline_comparison_normalizes_only_known_checkout_roots() -> None:
    result = CheckResult(
        name="typecheck",
        argv=["tsc"],
        status=CheckStatus.FAILED,
        exit_code=2,
        duration_seconds=0,
        output="/workspace/source/a.ts: TS100",
        workspace_root="/workspace/source",
        baseline_status=CheckStatus.FAILED,
        baseline_exit_code=2,
        baseline_output="/workspace/base/a.ts: TS100",
        baseline_workspace_root="/workspace/base",
    )
    assert _matches_baseline_failure(result)
    assert not _matches_baseline_failure(
        result.model_copy(update={"output": "/workspace/source/a.ts: TS200"})
    )


@pytest.mark.asyncio
async def test_check_planner_sees_companion_files_and_preserves_partial_evidence(
    tmp_path: Path,
) -> None:
    workspace, commit = _workspace(tmp_path)
    seen: list[str] = []

    async def repair(context: PreparationContext, checks: list[CheckResult]) -> RepairOutcome:
        (workspace / "companion.py").write_text("guard = True\n")
        return await _noop_repair(context, checks)

    async def planner(
        _context: PreparationContext,
        manifest: list[FileManifestEntry],
    ) -> list[CommandSpec]:
        seen.extend(item.path for item in manifest)
        return [CommandSpec(name="native tests", argv=["missing-runtime", "test"])]

    async def runner(_workspace: Path, command: CommandSpec) -> CheckResult:
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.UNAVAILABLE,
            exit_code=127,
            duration_seconds=0,
        )

    result = await prepare_fix(
        _request(_candidate(commit)),
        workspace,
        repair=repair,
        verify=_verified,
        check_planner=planner,
        command_runner=runner,
    )
    assert set(seen) == {"app.py", "companion.py"}
    assert result.state is PreparationState.BLOCKED
    assert result.verifier and result.verifier.regression_tests[0].passed()
    assert len(result.final_file_manifest) == 2
    assert result.attempts == 1


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

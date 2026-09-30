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
    RepairOutcome,
    RepairStatus,
    ReproductionSpec,
    SourceIdentity,
    SourceIdentityKind,
    VerificationDecision,
    VerifierResult,
    candidate_from_legacy_report,
)
from strix.fix.locations import AnchorStatus, anchor_location
from strix.fix.prepare import (
    PreparationContext,
    build_git_manifest,
    build_git_patch,
    prepare_fix,
    workspace_digest,
)


if TYPE_CHECKING:
    from pathlib import Path


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
    digest = await workspace_digest(context.workspace)
    results = [await _fixture_command(context.workspace, command) for command in commands]
    return RepairOutcome(
        status=RepairStatus.COMPLETE,
        summary="Fixed and tested.",
        command_results=results,
        source_digest=digest,
        turns_used=1,
    )


async def _fixture_command(workspace: Path, command: CommandSpec) -> CheckResult:
    """Run this module's synthetic fixture tests, without a production command wrapper."""
    process = await asyncio.create_subprocess_exec(
        command.argv[0],
        "-B",
        *command.argv[1:],
        cwd=workspace,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await process.communicate()
    return CheckResult(
        name=command.name,
        argv=command.argv,
        status=CheckStatus.PASSED if process.returncode == 0 else CheckStatus.FAILED,
        exit_code=process.returncode,
        duration_seconds=0,
        output=output.decode(),
    )


async def _verified(
    context: PreparationContext,
    _checks: list[CheckResult],
) -> VerifierResult:
    return VerifierResult(
        decision=VerificationDecision.VERIFIED,
        source_digest=context.feedback[-1].repair.source_digest,
        summary="The fix addresses the finding.",
        review_basis="code_review",
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
async def test_manifest_patch_includes_untracked_companion_file(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    (workspace / "companion.py").write_text("guard = True\n")
    manifest, _, _ = await build_git_manifest(workspace)
    patch = await build_git_patch(workspace, manifest)
    assert b"b/companion.py" in patch
    assert b"+guard = True" in patch
    _git(workspace, "diff", "--check")


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
    assert result.checks == outcome.command_results
    assert "Ran 1 test" in result.checks[0].output
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
@pytest.mark.parametrize("defect", ["missing_unit", "failed", "missing_request"])
async def test_agent_approval_owns_test_evidence_without_controller_retries(
    tmp_path: Path, defect: str
) -> None:
    workspace, commit = _workspace(tmp_path)

    async def repair(context, checks):
        result = await _noop_repair(context, checks)
        if defect == "missing_unit":
            result.command_results = [
                c for c in result.command_results if c.name != "existing suite"
            ]
        elif defect == "missing_request":
            result.command_results = [c for c in result.command_results if c.name != "compile"]
        else:
            check = result.command_results[0]
            check.status, check.exit_code = CheckStatus.FAILED, 1
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
        evidence[1] = await _fixture_command(workspace, command)
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
        _request(_candidate(commit)).model_copy(
            update={"timeout_seconds": 1 if stop == "timeout" else 30}
        ),
        workspace,
        repair=repair,
        verify=review,
        cancelled=lambda: cancel,
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

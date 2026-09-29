"""Repository fix preparation engine."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import os
import subprocess
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from strix.fix.contracts import (
    BlockerKind,
    CheckResult,
    CheckStatus,
    CommandSpec,
    FileManifestEntry,
    FixCandidateV1,
    FixPreparationAttempt,
    FixPreparationRequestV1,
    FixPreparationResultV1,
    PreparationBlocker,
    PreparationState,
    RepairOutcome,
    RepairStatus,
    VerificationDecision,
    VerifierResult,
)
from strix.fix.evidence import command_status
from strix.fix.locations import AnchorStatus, anchor_location


class PreparationCancelledError(RuntimeError):
    pass


CommandRunner = Callable[[Path, CommandSpec], Awaitable[CheckResult]]
ManifestBuilder = Callable[[Path], Awaitable[tuple[list[FileManifestEntry], str, str | None]]]
CancellationCheck = Callable[[], bool]


@dataclass(slots=True)
class PreparationPolicy:
    max_repair_attempts: int = 2
    timeout_seconds: int = 1800
    max_output_chars: int = 20000

    def __post_init__(self) -> None:
        if not 1 <= self.max_repair_attempts <= 2:
            raise ValueError("max_repair_attempts must be between 1 and 2")


@dataclass(slots=True)
class PreparationContext:
    request: FixPreparationRequestV1
    workspace: Path
    candidate: FixCandidateV1
    attempt: int = 0
    feedback: list[FixPreparationAttempt] = field(default_factory=list)


RepairAgent = Callable[
    [PreparationContext, list[CheckResult]],
    Awaitable[RepairOutcome | None],
]
IndependentVerifier = Callable[
    [PreparationContext, list[CheckResult]],
    Awaitable[VerifierResult],
]
SourceVerifier = Callable[[PreparationContext], Awaitable[bool]]
CheckPlanner = Callable[[PreparationContext, list[FileManifestEntry]], Awaitable[list[CommandSpec]]]


_COMMAND_ENV_ALLOWLIST = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONHOME",
        "PYTHONPATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "VIRTUAL_ENV",
        "SystemRoot",
    }
)


@functools.lru_cache(maxsize=1)
def _network_isolation_prefix() -> tuple[str, ...] | None:
    """Return a working ``unshare`` prefix that creates an empty network
    namespace, or None when the platform cannot isolate egress."""
    for prefix in (("unshare", "-Urn"), ("unshare", "-n")):
        try:
            probe = subprocess.run(  # noqa: S603
                [*prefix, "true"],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:
            return prefix
    return None


def _command_environment(credentials_allowed: Iterable[str]) -> dict[str, str]:
    allowed = _COMMAND_ENV_ALLOWLIST | set(credentials_allowed)
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


async def run_command(
    workspace: Path,
    command: CommandSpec,
    *,
    credentials_allowed: Iterable[str] = (),
    network_allowed: bool = False,
) -> CheckResult:
    started = time.monotonic()
    cwd = (workspace / command.cwd).resolve()
    if not cwd.is_relative_to(workspace.resolve()) or not cwd.is_dir():
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.UNAVAILABLE,
            duration_seconds=time.monotonic() - started,
            output="The command working directory is unavailable.",
            required=command.required,
        )
    argv = list(command.argv)
    if not network_allowed:
        prefix = _network_isolation_prefix()
        if prefix is None:
            return CheckResult(
                name=command.name,
                argv=command.argv,
                status=CheckStatus.UNAVAILABLE,
                duration_seconds=time.monotonic() - started,
                output="Network isolation is unavailable, so the command was not run.",
                required=command.required,
            )
        argv = [*prefix, *argv]
    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=_command_environment(credentials_allowed),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await asyncio.wait_for(process.communicate(), command.timeout_seconds)
    except (FileNotFoundError, PermissionError) as exc:
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.UNAVAILABLE,
            duration_seconds=time.monotonic() - started,
            output=str(exc),
            required=command.required,
        )
    except TimeoutError:
        if process is not None:
            process.kill()
            await process.wait()
        return CheckResult(
            name=command.name,
            argv=command.argv,
            status=CheckStatus.FAILED,
            duration_seconds=time.monotonic() - started,
            output=f"Timed out after {command.timeout_seconds} seconds.",
            required=command.required,
        )
    status, failure_kind = command_status(process.returncode or 0, output.decode(errors="replace"))
    return CheckResult(
        name=command.name,
        argv=command.argv,
        status=status,
        exit_code=process.returncode,
        duration_seconds=time.monotonic() - started,
        output=output.decode(errors="replace")[-20000:],
        required=command.required,
        failure_kind=failure_kind,
        cwd=command.cwd,
        workspace_root=str(workspace.resolve()),
    )


async def build_git_manifest(
    workspace: Path,
) -> tuple[list[FileManifestEntry], str, str | None]:
    process = await asyncio.create_subprocess_exec(
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "-z",
        cwd=workspace,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, error = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(error.decode(errors="replace"))

    entries: list[FileManifestEntry] = []
    changed_files: list[str] = []
    records = [record for record in output.decode(errors="replace").split("\0") if record]
    workspace_resolved = workspace.resolve()
    index = 0
    while index < len(records):
        record = records[index]
        status = record[:2]
        path_text = record[3:]
        if "R" in status or "C" in status:
            index += 1
        path = workspace / path_text
        changed_files.append(path_text)
        operation: Literal["add", "modify", "delete"]
        if status == "??" or "A" in status:
            operation = "add"
        elif "D" in status:
            operation = "delete"
        else:
            operation = "modify"
        resolved = path.resolve()
        contained = resolved.is_relative_to(workspace_resolved)
        if operation == "add" and contained and resolved.is_dir():
            for child in sorted(resolved.rglob("*")):
                child_resolved = child.resolve()
                if (
                    not child_resolved.is_file()
                    or not child_resolved.is_relative_to(workspace_resolved)
                    or ".git" in child.relative_to(resolved).parts
                ):
                    continue
                entries.append(
                    FileManifestEntry(
                        path=child_resolved.relative_to(workspace_resolved).as_posix(),
                        operation="add",
                        resulting_sha256=hashlib.sha256(child_resolved.read_bytes()).hexdigest(),
                    )
                )
            index += 1
            continue
        resulting = (
            hashlib.sha256(resolved.read_bytes()).hexdigest()
            if contained and resolved.is_file()
            else None
        )
        original: str | None = None
        if operation != "add":
            original_process = await asyncio.create_subprocess_exec(
                "git",
                "show",
                f"HEAD:{path_text}",
                cwd=workspace,
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            original_bytes, _ = await original_process.communicate()
            if original_process.returncode == 0:
                original = hashlib.sha256(original_bytes).hexdigest()
        entries.append(
            FileManifestEntry(
                path=path_text,
                operation=operation,
                original_sha256=original,
                resulting_sha256=resulting,
            )
        )
        index += 1

    summary = "\n".join(f"{entry.operation}: {entry.path}" for entry in entries)
    return entries, summary, None


async def build_git_patch(workspace: Path, manifest: list[FileManifestEntry]) -> bytes:
    """Include new files in the exact diff the reviewer and artifact consumer receive."""
    chunks: list[bytes] = []
    commands = [["git", "diff", "--binary", "HEAD", "--"]]
    for entry in manifest:
        if entry.operation == "add" and not await _tracked_in_index(workspace, entry.path):
            commands.append(  # noqa: PERF401 - requires sequential async index lookup
                ["git", "diff", "--no-index", "--binary", "--", "/dev/null", entry.path]
            )
    for argv in commands:
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=workspace, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        output, error = await process.communicate()
        if process.returncode not in {0, 1}:
            raise RuntimeError(error.decode(errors="replace"))
        chunks.append(output)
    return b"".join(chunks)


async def _tracked_in_index(workspace: Path, path: str) -> bool:
    process = await asyncio.create_subprocess_exec(
        "git",
        "ls-files",
        "--error-unmatch",
        "--",
        path,
        cwd=workspace,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return await process.wait() == 0


async def _workspace_digest(workspace: Path) -> str:
    manifest, _, _ = await build_git_manifest(workspace)
    payload = json.dumps(
        [entry.model_dump(mode="json") for entry in manifest],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


async def _verify_source(context: PreparationContext) -> bool:
    identity = context.candidate.source_identity
    if identity is None:
        return False
    if identity.kind == "commit":
        process = await asyncio.create_subprocess_exec(
            "git",
            "rev-parse",
            "HEAD",
            cwd=context.workspace,
            stdout=asyncio.subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        output, _ = await process.communicate()
        if process.returncode != 0 or output.decode().strip().lower() != identity.value:
            return False
    status_process = await asyncio.create_subprocess_exec(
        "git",
        "status",
        "--porcelain=v1",
        "-z",
        cwd=context.workspace,
        stdout=asyncio.subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    status_output, _ = await status_process.communicate()
    return status_process.returncode == 0 and not status_output.strip(b"\x00")


def _result(
    context: PreparationContext,
    *,
    state: PreparationState,
    reason: str,
    started: float,
    checks: list[CheckResult] | None = None,
    reproduction: CheckResult | None = None,
    verifier: VerifierResult | None = None,
    gaps: list[str] | None = None,
    manifest: list[FileManifestEntry] | None = None,
    diff_summary: str = "",
    artifact_ref: str | None = None,
    attempt_history: list[FixPreparationAttempt] | None = None,
    blocker: PreparationBlocker | None = None,
) -> FixPreparationResultV1:
    return FixPreparationResultV1(
        state=state,
        stop_reason=reason,
        source_identity=context.candidate.source_identity,
        candidate=context.candidate,
        candidate_digest=context.candidate.digest(),
        final_file_manifest=manifest or [],
        artifact_ref=artifact_ref,
        changed_files=[entry.path for entry in manifest or []],
        diff_summary=diff_summary,
        checks=checks or [],
        security_reproduction=reproduction,
        verifier=verifier,
        attempt_history=attempt_history or [],
        gaps=gaps or [],
        blocker=blocker,
        attempts=context.attempt,
        elapsed_seconds=time.monotonic() - started,
    )


def _repair_outcome(value: RepairOutcome | None) -> RepairOutcome:
    if value is not None:
        return value
    return RepairOutcome(
        status=RepairStatus.COMPLETE,
        summary="The repair implementation returned control for independent evaluation.",
    )


def _required_checks_pass(checks: list[CheckResult]) -> bool:
    required = [result for result in checks if result.required]
    return bool(required) and all(result.status is CheckStatus.PASSED for result in required)


def _verification_passes(
    checks: list[CheckResult],
    verifier: VerifierResult,
) -> bool:
    return (
        _required_checks_pass(checks)
        and verifier.decision is VerificationDecision.VERIFIED
        and verifier.security_invariant_closed
        and not verifier.gaps
        and verifier.blocker is None
        and bool(verifier.regression_tests)
        and all(result.passed() for result in verifier.regression_tests)
    )


def _verification_gaps(
    repair_outcome: RepairOutcome,
    checks: list[CheckResult],
    verifier: VerifierResult,
) -> list[str]:
    gaps = list(repair_outcome.gaps)
    required = [result for result in checks if result.required]
    if not required:
        gaps.append("No required repository check was configured.")
    gaps.extend(
        f"{result.name}: required check {result.status}"
        for result in required
        if result.status is not CheckStatus.PASSED
    )
    gaps.extend(
        f"{result.name}: optional check {result.status}"
        for result in checks
        if not result.required and result.status is not CheckStatus.PASSED
    )
    if not verifier.regression_tests or not all(
        item.passed() for item in verifier.regression_tests
    ):
        gaps.append(
            "A paired functional regression and legitimate-behavior test is still required."
        )
    if not verifier.reproduction_executed:
        gaps.append("The independent verifier did not execute the security reproduction.")
    if not verifier.security_invariant_closed:
        gaps.append("The independent verifier did not prove the security invariant.")
    gaps.extend(verifier.gaps)
    return list(dict.fromkeys(gaps))


def _matches_baseline_failure(result: CheckResult) -> bool:
    if result.baseline_status is not result.status or result.status not in {
        CheckStatus.FAILED,
        CheckStatus.UNAVAILABLE,
        CheckStatus.SKIPPED,
    }:
        return False
    if result.baseline_exit_code != result.exit_code:
        return False
    candidate_output = result.output
    baseline_output = result.baseline_output or ""
    if result.workspace_root:
        candidate_output = candidate_output.replace(result.workspace_root, "<repository>")
    if result.baseline_workspace_root:
        baseline_output = baseline_output.replace(result.baseline_workspace_root, "<repository>")
    candidate_output = " ".join(candidate_output.split())
    baseline_output = " ".join(baseline_output.split())
    return bool(candidate_output and candidate_output == baseline_output)


async def prepare_fix(  # noqa: PLR0915
    request: FixPreparationRequestV1,
    workspace: Path,
    *,
    repair: RepairAgent,
    verify: IndependentVerifier,
    command_runner: CommandRunner = run_command,
    manifest_builder: ManifestBuilder = build_git_manifest,
    source_verifier: SourceVerifier = _verify_source,
    check_planner: CheckPlanner | None = None,
    cancelled: CancellationCheck = lambda: False,
    policy: PreparationPolicy | None = None,
) -> FixPreparationResultV1:
    started = time.monotonic()
    resolved_policy = policy or PreparationPolicy(
        max_repair_attempts=request.max_repair_attempts,
        timeout_seconds=request.timeout_seconds,
    )
    context = PreparationContext(request=request, workspace=workspace, candidate=request.candidate)
    runner = command_runner
    if runner is run_command:
        runner = functools.partial(
            run_command,
            credentials_allowed=request.credentials_allowed,
            network_allowed=request.network_allowed,
        )
    checks: list[CheckResult] = []
    verifier: VerifierResult | None = None
    reproduction: CheckResult | None = None

    async def finish(
        state: PreparationState,
        reason: str,
        *,
        blocker: PreparationBlocker | None = None,
        gaps: list[str] | None = None,
    ) -> FixPreparationResultV1:
        manifest, summary, artifact = await manifest_builder(workspace)
        return _result(
            context,
            state=state,
            reason=reason,
            started=started,
            checks=checks,
            verifier=verifier,
            reproduction=reproduction,
            manifest=manifest,
            diff_summary=summary,
            artifact_ref=artifact,
            attempt_history=context.feedback,
            blocker=blocker,
            gaps=gaps,
        )

    async def execute() -> FixPreparationResultV1:  # noqa: PLR0911, PLR0912, PLR0915
        nonlocal checks, verifier, reproduction
        blocker: PreparationBlocker | None
        if cancelled():
            raise PreparationCancelledError
        if not await source_verifier(context):
            blocker = PreparationBlocker(
                kind=BlockerKind.SOURCE,
                summary="The repository no longer matches the finding source.",
                user_action="Refresh the finding against the current repository revision.",
            )
            return _result(
                context,
                state=PreparationState.STALE,
                reason=blocker.summary,
                blocker=blocker,
                started=started,
            )
        anchors = [
            anchor_location(workspace, location, exact_source=True)
            for location in context.candidate.finding_locations
        ]
        unresolved = [item for item in anchors if item.status is not AnchorStatus.UNIQUE]
        if unresolved:
            blocker = PreparationBlocker(
                kind=BlockerKind.SOURCE,
                summary="The reported finding locations could not be resolved uniquely.",
                user_action="Refresh the finding or identify the affected source location.",
                details=[f"{item.location.file}: {item.status}" for item in unresolved],
            )
            return await finish(PreparationState.BLOCKED, blocker.summary, blocker=blocker)
        context.candidate = context.candidate.model_copy(
            update={"finding_locations": [item.location for item in anchors]}
        )
        for attempt in range(1, resolved_policy.max_repair_attempts + 1):
            context.attempt = attempt
            if cancelled():
                raise PreparationCancelledError
            verifier = None
            reproduction = None
            record = FixPreparationAttempt(
                attempt=attempt,
                repair=RepairOutcome(status=RepairStatus.INCOMPLETE, summary="Repair started."),
                workspace_digest=await _workspace_digest(workspace),
            )
            context.feedback.append(record)
            record.repair = _repair_outcome(await repair(context, checks))
            record.workspace_digest = await _workspace_digest(workspace)
            manifest, _, _ = await build_git_manifest(workspace)
            if not manifest:
                if record.repair.blocker:
                    return await finish(
                        PreparationState.BLOCKED,
                        record.repair.summary,
                        blocker=record.repair.blocker,
                        gaps=record.repair.gaps,
                    )
                return await finish(
                    PreparationState.FAILED, "The repair did not change repository source."
                )
            planned = await check_planner(context, manifest) if check_planner else request.checks
            # Retain partial execution if a later command is interrupted.
            checks = record.checks
            for command in planned:
                if cancelled():
                    raise PreparationCancelledError
                checks.append(await runner(workspace, command))
            required = [item for item in checks if item.required]
            regressions = [
                item
                for item in required
                if item.status is CheckStatus.FAILED and not _matches_baseline_failure(item)
            ]
            unchanged_retry = (
                len(context.feedback) > 1
                and context.feedback[-2].workspace_digest == record.workspace_digest
            )
            can_retry = (
                record.repair.status is RepairStatus.COMPLETE
                and attempt < resolved_policy.max_repair_attempts
                and not unchanged_retry
            )
            if regressions:
                if can_retry:
                    continue
                return await finish(
                    PreparationState.FAILED,
                    "The repair did not pass the repository quality gate.",
                    gaps=[f"{item.name}: {item.output}" for item in regressions],
                )
            # Missing tools and pre-existing failures do not erase attainable security evidence.
            verifier = await verify(context, checks)
            record.verifier = verifier
            reproduction = next(
                (item.patched for item in reversed(verifier.regression_tests) if item.passed()),
                verifier.regression_tests[-1].patched if verifier.regression_tests else None,
            )
            record.security_reproduction = reproduction
            gaps = _verification_gaps(record.repair, checks, verifier)
            if record.workspace_digest != await _workspace_digest(workspace):
                return await finish(
                    PreparationState.FAILED,
                    "Verification changed the prepared source; its evidence cannot "
                    "approve this artifact.",
                )
            if verifier.decision is VerificationDecision.REJECTED:
                if verifier.repairable and can_retry:
                    continue
                return await finish(
                    PreparationState.FAILED,
                    "The independent security verifier found a repair defect.",
                    gaps=gaps,
                )
            if record.repair.status is not RepairStatus.COMPLETE:
                state = (
                    PreparationState.BLOCKED
                    if record.repair.status is RepairStatus.BLOCKED
                    else PreparationState.FAILED
                )
                return await finish(
                    state,
                    record.repair.summary,
                    blocker=record.repair.blocker,
                    gaps=gaps,
                )
            if _verification_passes(checks, verifier) and not record.repair.gaps:
                return await finish(
                    PreparationState.READY,
                    "The fix passed relevant repository checks and functional security "
                    "verification.",
                    gaps=gaps,
                )
            unavailable = [
                item
                for item in required
                if item.status
                in {CheckStatus.UNAVAILABLE, CheckStatus.SKIPPED, CheckStatus.CANCELLED}
            ]
            baseline = [item for item in required if _matches_baseline_failure(item)]
            blocker = verifier.blocker
            if blocker is None:
                if unavailable or not required:
                    blocker = PreparationBlocker(
                        kind=BlockerKind.ENVIRONMENT,
                        summary=(
                            "The patch is prepared, but required repository checks could not run."
                        ),
                        user_action=(
                            "Resolve the reported setup requirement and rerun verification."
                        ),
                        details=[f"{item.name}: {item.output}" for item in unavailable]
                        or ["No relevant repository quality check was identified."],
                    )
                elif baseline:
                    blocker = PreparationBlocker(
                        kind=BlockerKind.REPOSITORY_BASELINE,
                        summary="Required checks also fail on the unchanged repository.",
                        user_action=(
                            "Resolve the existing check failure or provide an authoritative "
                            "replacement check."
                        ),
                        details=[item.name for item in baseline],
                    )
                else:
                    blocker = PreparationBlocker(
                        kind=BlockerKind.SECURITY_EVIDENCE,
                        summary="The patch is prepared, but functional verification is incomplete.",
                        user_action=(
                            "Provide the missing test prerequisites or review the remaining "
                            "evidence gaps."
                        ),
                        details=gaps,
                    )
            return await finish(
                PreparationState.BLOCKED, blocker.summary, blocker=blocker, gaps=gaps
            )
        return await finish(
            PreparationState.FAILED, "The repair exhausted its configured attempts."
        )

    try:
        async with asyncio.timeout(resolved_policy.timeout_seconds):
            return await execute()
    except PreparationCancelledError:
        return await finish(PreparationState.FAILED, "Fix preparation was cancelled.")
    except TimeoutError:
        return await finish(PreparationState.FAILED, "Fix preparation exceeded its time limit.")
    except Exception as error:  # noqa: BLE001
        # Preserve partial work without exposing unredacted exception text.
        return await finish(
            PreparationState.FAILED,
            f"Fix preparation stopped after {type(error).__name__}; partial work was retained.",
        )

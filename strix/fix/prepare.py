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
    VerificationTarget,
    VerifierResult,
)
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
    return CheckResult(
        name=command.name,
        argv=command.argv,
        status=CheckStatus.PASSED if process.returncode == 0 else CheckStatus.FAILED,
        exit_code=process.returncode,
        duration_seconds=time.monotonic() - started,
        output=output.decode(errors="replace")[-20000:],
        required=command.required,
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

    summary_process = await asyncio.create_subprocess_exec(
        "git",
        "diff",
        "--stat",
        "--",
        cwd=workspace,
        stdout=asyncio.subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    summary, _ = await summary_process.communicate()
    return entries, summary.decode(errors="replace").strip(), None


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
        and verifier.reproduction_executed
        and any(
            result.target is VerificationTarget.PATCHED and result.status is CheckStatus.PASSED
            for result in verifier.security_tests
        )
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
    if not verifier.security_tests:
        gaps.append("The independent verifier did not execute a security test.")
    elif not any(
        result.target is VerificationTarget.PATCHED and result.status is CheckStatus.PASSED
        for result in verifier.security_tests
    ):
        gaps.append("The independent verifier did not pass a security test on the patch.")
    if not verifier.reproduction_executed:
        gaps.append("The independent verifier did not execute the security reproduction.")
    if not verifier.security_invariant_closed:
        gaps.append("The independent verifier did not prove the security invariant.")
    gaps.extend(verifier.gaps)
    return list(dict.fromkeys(gaps))


async def prepare_fix(  # noqa: PLR0915
    request: FixPreparationRequestV1,
    workspace: Path,
    *,
    repair: RepairAgent,
    verify: IndependentVerifier,
    command_runner: CommandRunner = run_command,
    manifest_builder: ManifestBuilder = build_git_manifest,
    source_verifier: SourceVerifier = _verify_source,
    cancelled: CancellationCheck = lambda: False,
    policy: PreparationPolicy | None = None,
) -> FixPreparationResultV1:
    started = time.monotonic()
    resolved_policy = policy or PreparationPolicy(
        max_repair_attempts=request.max_repair_attempts,
        timeout_seconds=request.timeout_seconds,
    )
    context = PreparationContext(request=request, workspace=workspace, candidate=request.candidate)
    runner: CommandRunner = command_runner
    if runner is run_command:
        runner = functools.partial(
            run_command,
            credentials_allowed=request.credentials_allowed,
            network_allowed=request.network_allowed,
        )

    async def execute() -> FixPreparationResultV1:  # noqa: PLR0911, PLR0912, PLR0915
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
            anchor_location(workspace, location) for location in context.candidate.finding_locations
        ]
        if any(result.status is not AnchorStatus.UNIQUE for result in anchors):
            details = [
                f"{result.location.file}: {result.status}"
                for result in anchors
                if result.status is not AnchorStatus.UNIQUE
            ]
            blocker = PreparationBlocker(
                kind=BlockerKind.SOURCE,
                summary="The reported finding locations could not be resolved uniquely.",
                user_action="Refresh the finding or identify the affected source location.",
                details=details,
            )
            return _result(
                context,
                state=PreparationState.BLOCKED,
                reason=blocker.summary,
                gaps=details,
                blocker=blocker,
                started=started,
            )
        context.candidate = context.candidate.model_copy(
            update={"finding_locations": [result.location for result in anchors]}
        )

        checks: list[CheckResult] = []
        verifier: VerifierResult | None = None
        attempt_history: list[FixPreparationAttempt] = []
        for attempt in range(1, resolved_policy.max_repair_attempts + 1):
            context.attempt = attempt
            if cancelled():
                raise PreparationCancelledError
            repair_outcome = _repair_outcome(await repair(context, checks))

            if repair_outcome.status is RepairStatus.BLOCKED:
                manifest, summary, artifact_ref = await manifest_builder(workspace)
                blocker = repair_outcome.blocker or PreparationBlocker(
                    kind=BlockerKind.EXTERNAL_CONFIGURATION,
                    summary=repair_outcome.summary,
                    user_action=(
                        "Provide the missing repository, credential, or production "
                        "configuration prerequisite."
                    ),
                    details=repair_outcome.gaps,
                )
                return _result(
                    context,
                    state=PreparationState.BLOCKED,
                    reason=blocker.summary,
                    gaps=repair_outcome.gaps,
                    manifest=manifest,
                    diff_summary=summary,
                    artifact_ref=artifact_ref,
                    attempt_history=attempt_history,
                    blocker=blocker,
                    started=started,
                )

            if repair_outcome.status is not RepairStatus.COMPLETE:
                manifest, summary, artifact_ref = await manifest_builder(workspace)
                return _result(
                    context,
                    state=PreparationState.FAILED,
                    reason=repair_outcome.summary,
                    gaps=repair_outcome.gaps,
                    manifest=manifest,
                    diff_summary=summary,
                    artifact_ref=artifact_ref,
                    attempt_history=attempt_history,
                    started=started,
                )

            checks = [await runner(workspace, check) for check in request.checks]
            workspace_digest = await _workspace_digest(workspace)
            attempt_record = FixPreparationAttempt(
                attempt=attempt,
                repair=repair_outcome,
                checks=checks,
                workspace_digest=workspace_digest,
            )
            attempt_history.append(attempt_record)
            context.feedback = list(attempt_history)

            required = [result for result in checks if result.required]
            unavailable = [
                result for result in required if result.status is CheckStatus.UNAVAILABLE
            ]
            if not required or unavailable:
                details = (
                    ["No required repository quality check was configured."]
                    if not required
                    else [f"{result.name}: {result.output}" for result in unavailable]
                )
                blocker = PreparationBlocker(
                    kind=BlockerKind.ENVIRONMENT,
                    summary="The repository quality gate could not run.",
                    user_action=(
                        "Provide the missing tool or repository setup needed to run "
                        "the required checks."
                    ),
                    details=details,
                )
                manifest, summary, artifact_ref = await manifest_builder(workspace)
                return _result(
                    context,
                    state=PreparationState.BLOCKED,
                    reason=blocker.summary,
                    checks=checks,
                    gaps=blocker.details,
                    manifest=manifest,
                    diff_summary=summary,
                    artifact_ref=artifact_ref,
                    attempt_history=attempt_history,
                    blocker=blocker,
                    started=started,
                )

            failed = [result for result in required if result.status is CheckStatus.FAILED]
            baseline_failures = [
                result for result in failed if result.baseline_status is CheckStatus.FAILED
            ]
            if baseline_failures:
                blocker = PreparationBlocker(
                    kind=BlockerKind.REPOSITORY_BASELINE,
                    summary="Required checks also fail on the unchanged repository.",
                    user_action=(
                        "Repair the repository baseline or identify authoritative "
                        "replacement checks."
                    ),
                    details=[result.name for result in baseline_failures],
                )
                manifest, summary, artifact_ref = await manifest_builder(workspace)
                return _result(
                    context,
                    state=PreparationState.BLOCKED,
                    reason=blocker.summary,
                    checks=checks,
                    gaps=blocker.details,
                    manifest=manifest,
                    diff_summary=summary,
                    artifact_ref=artifact_ref,
                    attempt_history=attempt_history,
                    blocker=blocker,
                    started=started,
                )
            if failed:
                if attempt < resolved_policy.max_repair_attempts:
                    continue
                manifest, summary, artifact_ref = await manifest_builder(workspace)
                return _result(
                    context,
                    state=PreparationState.FAILED,
                    reason="The repair did not pass the repository quality gate.",
                    checks=checks,
                    gaps=[f"{result.name}: {result.output}" for result in failed],
                    manifest=manifest,
                    diff_summary=summary,
                    artifact_ref=artifact_ref,
                    attempt_history=attempt_history,
                    started=started,
                )

            verifier = await verify(context, checks)
            attempt_record.verifier = verifier
            attempt_record.security_reproduction = next(
                (
                    result
                    for result in verifier.security_tests
                    if result.target is VerificationTarget.PATCHED
                ),
                None,
            )
            context.feedback = list(attempt_history)
            gaps = _verification_gaps(repair_outcome, checks, verifier)

            if verifier.blocker is not None:
                manifest, summary, artifact_ref = await manifest_builder(workspace)
                return _result(
                    context,
                    state=PreparationState.BLOCKED,
                    reason=verifier.blocker.summary,
                    checks=checks,
                    reproduction=attempt_record.security_reproduction,
                    verifier=verifier,
                    gaps=gaps,
                    manifest=manifest,
                    diff_summary=summary,
                    artifact_ref=artifact_ref,
                    attempt_history=attempt_history,
                    blocker=verifier.blocker,
                    started=started,
                )

            if _verification_passes(checks, verifier):
                manifest, summary, artifact_ref = await manifest_builder(workspace)
                if not manifest:
                    return _result(
                        context,
                        state=PreparationState.FAILED,
                        reason="The repair did not change repository source.",
                        checks=checks,
                        verifier=verifier,
                        gaps=["No prepared source change was produced."],
                        attempt_history=attempt_history,
                        started=started,
                    )
                return _result(
                    context,
                    state=PreparationState.READY,
                    reason="The fix passed repository checks and security verification.",
                    checks=checks,
                    reproduction=attempt_record.security_reproduction,
                    verifier=verifier,
                    manifest=manifest,
                    diff_summary=summary,
                    artifact_ref=artifact_ref,
                    attempt_history=attempt_history,
                    started=started,
                )

            if verifier.repairable and attempt < resolved_policy.max_repair_attempts:
                continue

            manifest, summary, artifact_ref = await manifest_builder(workspace)
            return _result(
                context,
                state=PreparationState.FAILED,
                reason="The independent security verifier did not approve the repair.",
                checks=checks,
                reproduction=attempt_record.security_reproduction,
                verifier=verifier,
                gaps=gaps,
                manifest=manifest,
                diff_summary=summary,
                artifact_ref=artifact_ref,
                attempt_history=attempt_history,
                started=started,
            )

        manifest, summary, artifact_ref = await manifest_builder(workspace)
        return _result(
            context,
            state=PreparationState.FAILED,
            reason="The repair did not satisfy the required gates.",
            checks=checks,
            verifier=verifier,
            manifest=manifest,
            diff_summary=summary,
            artifact_ref=artifact_ref,
            attempt_history=attempt_history,
            started=started,
        )

    try:
        async with asyncio.timeout(resolved_policy.timeout_seconds):
            return await execute()
    except PreparationCancelledError:
        return _result(
            context,
            state=PreparationState.FAILED,
            reason="Fix preparation was cancelled.",
            attempt_history=context.feedback,
            started=started,
        )
    except TimeoutError:
        return _result(
            context,
            state=PreparationState.FAILED,
            reason="Fix preparation exceeded its time limit.",
            attempt_history=context.feedback,
            started=started,
        )

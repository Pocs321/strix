"""Repository fix preparation engine."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
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
from strix.fix.evidence import command_status, record_test_execution
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
    feedback: list[FixPreparationAttempt] = field(default_factory=list[FixPreparationAttempt])


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
        validation_mode="native_tests",
        test_plan=context.feedback[-1].repair.test_plan if context.feedback else None,
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
    return bool(required) and all(
        result.status is CheckStatus.PASSED and result.exit_code == 0 for result in required
    )


def _verification_passes(checks: list[CheckResult], verifier: VerifierResult) -> bool:
    return (
        _required_checks_pass(checks)
        and any(
            item.purpose == "regression" and item.status is CheckStatus.PASSED for item in checks
        )
        and len({item.environment_id for item in checks if item.environment_id}) <= 1
        and len({item.source_digest for item in checks if item.source_digest}) <= 1
        and verifier.decision is VerificationDecision.VERIFIED
        and verifier.security_invariant_closed
        and verifier.regression_test_valid
        and verifier.unit_test_coverage_valid
        and verifier.review_basis in {"execution", "code_review"}
        and not verifier.gaps
        and verifier.blocker is None
    )


def _test_plan_gaps(repair: RepairOutcome, manifest: list[FileManifestEntry]) -> list[str]:
    plan = repair.test_plan
    if plan is None:
        return ["The repair must supply a regression test and the repository unit-test commands."]
    changed = {entry.path for entry in manifest if entry.operation != "delete"}
    missing = [path for path in plan.regression_files if path not in changed]
    return [f"Regression test must be added or updated in the patch: {path}" for path in missing]


def _test_commands(repair: RepairOutcome) -> list[CommandSpec]:
    plan = repair.test_plan
    if plan is None:
        return []
    return [
        plan.regression_test.model_copy(update={"purpose": "regression", "required": True}),
        *(
            item.model_copy(update={"purpose": "unit", "required": True})
            for item in plan.unit_tests
        ),
    ]


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
        retained_verifier = verifier or (
            context.feedback[-1].verifier if context.feedback else None
        )
        return _result(
            context,
            state=state,
            reason=reason,
            started=started,
            checks=checks,
            verifier=retained_verifier,
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
            checks = record.checks
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
            await manifest_builder(workspace)  # Save the patch before any test can fail.
            can_retry = (
                attempt < resolved_policy.max_repair_attempts
                and record.repair.status is not RepairStatus.BLOCKED
            )
            plan_gaps = _test_plan_gaps(record.repair, manifest)
            if plan_gaps:
                record.repair.gaps = list(dict.fromkeys([*record.repair.gaps, *plan_gaps]))
                if can_retry:
                    continue
                return await finish(
                    PreparationState.BLOCKED,
                    "The patch is saved, but its regression-test handoff is incomplete.",
                    blocker=record.repair.blocker,
                    gaps=record.repair.gaps,
                )
            additional = await check_planner(context, manifest) if check_planner else request.checks
            planned = [*_test_commands(record.repair), *additional]
            unique: dict[tuple[str, tuple[str, ...], str], CommandSpec] = {}
            for command in planned:
                key = (command.purpose, tuple(command.argv), command.cwd)
                previous = unique.get(key)
                unique[key] = command.model_copy(
                    update={"required": command.required or bool(previous and previous.required)}
                )
            checks = record.checks
            for command in unique.values():
                if cancelled():
                    raise PreparationCancelledError
                checks.append(record_test_execution(await runner(workspace, command), command))
            reproduction = next((item for item in checks if item.purpose == "regression"), None)
            record.security_reproduction = reproduction
            failed = [
                item
                for item in checks
                if item.required and (item.status is not CheckStatus.PASSED or item.exit_code != 0)
            ]
            if failed:
                if can_retry:
                    continue
                return await finish(
                    PreparationState.BLOCKED,
                    "The patch is saved, but required tests or checks have not passed.",
                    blocker=PreparationBlocker(
                        kind=BlockerKind.VERIFICATION_RUNTIME,
                        summary="Required tests or checks have not passed.",
                        user_action="Review the recorded failures and retry after resolving them.",
                        details=[f"{item.name}: {item.status}" for item in failed],
                    ),
                    gaps=[f"{item.name}: {item.status}" for item in failed],
                )
            # Review the exact repair and its native test results. No second harness is required.
            verifier = await verify(context, checks)
            record.verifier = verifier
            if record.workspace_digest != await _workspace_digest(workspace):
                return await finish(
                    PreparationState.FAILED,
                    "Review changed the prepared source; validation must be rerun.",
                )
            if verifier.decision is VerificationDecision.REJECTED:
                if verifier.repairable and can_retry:
                    continue
                return await finish(
                    PreparationState.FAILED,
                    "The independent reviewer found a repair or regression-test defect.",
                    gaps=verifier.gaps,
                )
            if record.repair.status is RepairStatus.BLOCKED:
                return await finish(
                    PreparationState.BLOCKED,
                    record.repair.summary,
                    blocker=record.repair.blocker,
                    gaps=record.repair.gaps,
                )
            if _verification_passes(checks, verifier) and not record.repair.gaps:
                return await finish(
                    PreparationState.READY,
                    "Tests and required checks passed; independent review approved a draft PR.",
                )
            gaps = list(dict.fromkeys([*record.repair.gaps, *verifier.gaps]))
            if not gaps:
                gaps = ["Independent review could not confirm the repair and native-test coverage."]
            return await finish(
                PreparationState.BLOCKED,
                "The patch and test results are saved, but independent review is incomplete.",
                blocker=verifier.blocker
                or PreparationBlocker(
                    kind=BlockerKind.VERIFICATION_RUNTIME,
                    summary="Independent review is incomplete.",
                    user_action="Retry review of the saved changes and test evidence.",
                    details=gaps,
                ),
                gaps=gaps,
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
    except Exception as error:
        logging.getLogger(__name__).exception(
            "Fix preparation failed during attempt %s", context.attempt
        )
        # Preserve partial work without exposing unredacted exception text.
        return await finish(
            PreparationState.FAILED,
            f"Fix preparation stopped after {type(error).__name__}; partial work was retained.",
        )

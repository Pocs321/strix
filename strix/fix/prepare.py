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
from strix.fix.evidence import command_status


class PreparationCancelledError(RuntimeError):
    pass


CommandRunner = Callable[[Path, CommandSpec], Awaitable[CheckResult]]
ManifestBuilder = Callable[[Path], Awaitable[tuple[list[FileManifestEntry], str, str | None]]]
CancellationCheck = Callable[[], bool]


@dataclass(slots=True)
class PreparationPolicy:
    timeout_seconds: int = 7200
    max_output_chars: int = 20000


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
EvidenceReader = Callable[[], Awaitable[list[CheckResult]]]


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
        validation_mode="agent_review",
        prepared_source_digest=(
            context.feedback[-1].repair.source_digest if context.feedback else None
        ),
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


async def prepare_fix(  # noqa: PLR0915 - thin orchestration and cleanup
    request: FixPreparationRequestV1,
    workspace: Path,
    *,
    repair: RepairAgent,
    verify: IndependentVerifier,
    manifest_builder: ManifestBuilder = build_git_manifest,
    source_verifier: SourceVerifier = _verify_source,
    evidence_reader: EvidenceReader | None = None,
    cancelled: CancellationCheck = lambda: False,
    policy: PreparationPolicy | None = None,
) -> FixPreparationResultV1:
    """Run repair/review conversations; agents own setup, tests and corrections."""
    started = time.monotonic()
    resolved_policy = policy or PreparationPolicy(timeout_seconds=request.timeout_seconds)
    context = PreparationContext(request=request, workspace=workspace, candidate=request.candidate)
    checks: list[CheckResult] = []
    verifier: VerifierResult | None = None
    repair_turns = review_turns = 0

    async def finish(
        state: PreparationState,
        reason: str,
        *,
        blocker: PreparationBlocker | None = None,
        gaps: list[str] | None = None,
    ) -> FixPreparationResultV1:
        nonlocal checks
        if evidence_reader:
            checks = await evidence_reader()
        manifest, summary, artifact = await manifest_builder(workspace)
        return _result(
            context,
            state=state,
            reason=reason,
            started=started,
            checks=checks,
            verifier=verifier,
            manifest=manifest,
            diff_summary=summary,
            artifact_ref=artifact,
            attempt_history=context.feedback,
            blocker=blocker,
            gaps=gaps,
            reproduction=next((c for c in checks if c.purpose == "regression"), None),
        )

    async def execute() -> FixPreparationResultV1:  # noqa: PLR0911 - explicit terminal outcomes
        nonlocal checks, verifier, repair_turns, review_turns
        if cancelled():
            raise PreparationCancelledError
        if not await source_verifier(context):
            return await finish(
                PreparationState.STALE,
                "The repository no longer matches the finding source.",
                blocker=PreparationBlocker(
                    kind=BlockerKind.SOURCE,
                    summary="The repository no longer matches the finding source.",
                    user_action="Refresh the finding against the current repository revision.",
                ),
            )
        # Location/snippet interpretation belongs to repair. Exact source identity is checked above.
        while repair_turns < request.max_agent_turns and review_turns < request.max_agent_turns:
            if cancelled():
                raise PreparationCancelledError
            context.attempt += 1
            verifier = None
            record = FixPreparationAttempt(
                attempt=context.attempt,
                repair=RepairOutcome(status=RepairStatus.INCOMPLETE, summary="Repair started."),
                workspace_digest=await _workspace_digest(workspace),
            )
            context.feedback.append(record)
            record.repair = _repair_outcome(await repair(context, checks))
            repair_turns += max(1, record.repair.turns_used)
            checks = await evidence_reader() if evidence_reader else record.repair.command_results
            record.checks = list(checks)
            record.workspace_digest = await _workspace_digest(workspace)
            manifest, _, _ = await manifest_builder(workspace)
            if record.repair.status is not RepairStatus.COMPLETE:
                return await finish(
                    PreparationState.BLOCKED,
                    record.repair.summary,
                    blocker=record.repair.blocker,
                    gaps=record.repair.gaps,
                )
            if not manifest:
                return await finish(
                    PreparationState.BLOCKED,
                    "Repair completed without a deliverable patch.",
                )
            if cancelled():
                raise PreparationCancelledError
            # Review can investigate even incomplete validation and run the missing checks itself.
            verifier = await verify(context, checks)
            review_turns += max(1, verifier.turns_used)
            record.verifier = verifier
            if evidence_reader:
                checks = await evidence_reader()
                record.checks = list(checks)
            if verifier.blocker:
                return await finish(
                    PreparationState.BLOCKED,
                    verifier.summary,
                    blocker=verifier.blocker,
                    gaps=verifier.gaps,
                )
            if verifier.decision is VerificationDecision.REJECTED:
                record.repair.gaps.extend(verifier.gaps or [verifier.summary])
                continue
            if verifier.decision is not VerificationDecision.VERIFIED:
                return await finish(PreparationState.BLOCKED, verifier.summary, gaps=verifier.gaps)
            # Test selection, failures, reruns and coverage belong to the reviewer.
            # Only the artifact identity is checked here; it never starts another repair.
            if (
                record.workspace_digest != await _workspace_digest(workspace)
                or verifier.source_digest != record.repair.source_digest
            ):
                return await finish(
                    PreparationState.BLOCKED,
                    "The deliverable changed during review; "
                    "the approved patch cannot be delivered.",
                )
            return await finish(
                PreparationState.READY,
                "Independent review approved the draft PR. See the review for validation results.",
            )
        return await finish(
            PreparationState.BLOCKED,
            "The agent turn budget was reached; partial work was retained.",
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
        return await finish(
            PreparationState.FAILED,
            f"Fix preparation stopped after {type(error).__name__}; partial work was retained.",
        )

"""Run finding-scoped Fix tasks in the live scan sandbox."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import logging
import shutil
import subprocess
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.fix.contracts import FixCandidateV1, FixPreparationRequestV1, FixPreparationResultV1
from strix.fix.runtime import _RuntimeEnvironment, run_fix_preparation
from strix.fix.session import WorktreeSession
from strix.fix.workspace import git_metadata_archive
from strix.utils.secret_files import open_secret_file


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession

    from strix.core.agents import AgentCoordinator
    from strix.core.hooks import ReportUsageHooks

logger = logging.getLogger(__name__)
FixSink = Callable[
    [str, dict[str, Any], FixPreparationResultV1 | None, Path | None], Awaitable[bool | None]
]


class ScanFixes:
    def __init__(
        self,
        *,
        session: BaseSandboxSession,
        coordinator: AgentCoordinator,
        parent_id: str,
        scan_id: str,
        state_dir: Path,
        local_sources: list[dict[str, Any]],
        hooks: ReportUsageHooks,
        event_sink: Any = None,
        sink: FixSink | None = None,
    ) -> None:
        self.session, self.coordinator, self.parent_id = session, coordinator, parent_id
        self.scan_id, self.directory = scan_id, state_dir / "fixes"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.path = self.directory / "tasks.json"
        self.records: dict[str, Any] = (
            json.loads(self.path.read_text()) if self.path.exists() else {}
        )
        self.sources = [
            Path(s["source_path"]).resolve()
            for s in local_sources
            if s.get("source_path") and (Path(s["source_path"]) / ".git").exists()
        ]
        self.source_roots = {
            Path(
                s["source_path"]
            ).resolve(): f"/workspace/{s.get('workspace_subdir') or Path(s['source_path']).name}"
            for s in local_sources
            if s.get("source_path")
        }
        self.hooks, self.event_sink, self.sink = hooks, event_sink, sink
        self.tasks: dict[str, asyncio.Task[None]] = {}
        self.loop = asyncio.get_running_loop()
        self.closed = False
        self.base = f"/workspace/.strix-fixes/{hashlib.sha256(scan_id.encode()).hexdigest()[:16]}"
        self._source_lock = asyncio.Lock()
        self._staged: set[str] = set()

    def _save(self) -> None:
        temporary = self.path.with_suffix(".tmp")
        with open_secret_file(temporary) as stream:
            stream.write(json.dumps(self.records).encode())
        temporary.replace(self.path)

    def notify(self, report: dict[str, Any]) -> None:
        # Reporting callbacks can execute on a worker thread.
        self.loop.call_soon_threadsafe(self._schedule, report)

    def _schedule(self, report: dict[str, Any]) -> None:
        if self.closed:
            return
        finding_id = str(report["id"])
        try:
            candidate = FixCandidateV1.model_validate(report.get("fix_candidate"))
            eligible = (
                not report.get("deletion")
                and report.get("validation_status") == "confirmed"
                and candidate.finding is not None
                and candidate.finding.validation_status == "confirmed"
                and not candidate.blocker
                and bool(candidate.draft_edits)
                and candidate.source_identity is not None
            )
        except ValueError:
            eligible = False
            candidate = None
        digest = candidate.digest() if eligible and candidate else None
        previous = self.records.get(finding_id, {})
        if (
            digest
            and previous.get("digest") == digest
            and (finding_id in self.tasks or previous.get("status") != "running")
        ):
            return
        old_task = self.tasks.get(finding_id)
        if old_task and not old_task.done():
            old_task.cancel()
        if not digest or not candidate:
            if previous:
                previous["status"] = "obsolete"
                previous.pop("artifact", None)
                self._save()
            return
        used = int(previous.get("turns", 0))
        if used >= 300:
            return
        resume = previous.get("digest") == digest and previous.get("status") == "running"
        self.records[finding_id] = {"digest": digest, "turns": used, "status": "running"}
        self._save()
        self.tasks[finding_id] = asyncio.create_task(
            self._run(report, candidate, resume=resume, previous=old_task),
            name=f"fix-{finding_id}",
        )

    async def _emit(
        self,
        stage: str,
        report: dict[str, Any],
        result: FixPreparationResultV1 | None = None,
        artifact: Path | None = None,
    ) -> bool:
        if self.sink is None:
            return True
        return await self.sink(stage, report, result, artifact) is not False

    async def _stage_base(self, source: Path) -> str:
        key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
        base = f"{self.base}/repositories/{key}"
        async with self._source_lock:
            if key not in self._staged:
                # Scan metadata can be read-only. Use a sanitized local Git object
                # store for worktree bookkeeping, never alter the assessment checkout.
                exists = await self.session.exec(
                    "test", "-d", f"{base}/.git", shell=False, timeout=30
                )
                if exists.exit_code:
                    archive = f"{self.base}/repository-{key}.tar"
                    await self.session.exec("mkdir", "-p", base, shell=False, timeout=30)
                    data = await asyncio.to_thread(git_metadata_archive, source)
                    await self.session.write(Path(archive), io.BytesIO(data))
                    await self._exec("tar", "--no-same-owner", "-xf", archive, "-C", base)
                    await self._exec("rm", "-f", archive)
                self._staged.add(key)
        return base

    async def _exec(self, *argv: str) -> None:
        result = await self.session.exec(*argv, shell=False, timeout=120)
        if result.exit_code:
            raise RuntimeError(f"Workspace command failed: {argv[0]}")

    async def _run(  # noqa: PLR0912, PLR0915
        self,
        report: dict[str, Any],
        candidate: FixCandidateV1,
        *,
        resume: bool,
        previous: asyncio.Task[None] | None,
    ) -> None:
        finding_id, digest = str(report["id"]), candidate.digest()
        key = hashlib.sha256(f"{finding_id}:{digest}".encode()).hexdigest()[:24]
        agent_id = f"fix-{key}"
        root = f"{self.base}/worktrees/{key}"
        directory = self.directory / key
        artifact = directory / "prepared-fix.zip"
        borrowed: WorktreeSession | None = None
        base: str | None = None
        result: FixPreparationResultV1 | None = None
        started = False
        try:
            if previous:
                await asyncio.gather(previous, return_exceptions=True)
            if not await self._emit("started", report):
                return
            started = True
            if len(self.sources) != 1 or candidate.source_identity is None:
                raise ValueError("Fix requires one identified Git source checkout")  # noqa: TRY301
            source = self.sources[0]
            commit = candidate.source_identity.value
            directory.mkdir(parents=True, exist_ok=True)
            mirror = directory / "source"
            if not mirror.exists():
                await asyncio.to_thread(_clone_revision, source, mirror, commit)
            base = await self._stage_base(source)
            exists = await self.session.exec("test", "-d", root, shell=False, timeout=30)
            if resume and exists.exit_code:
                raise RuntimeError(  # noqa: TRY301
                    "The previous fix workspace is unavailable; no automatic restart"
                )
            if exists.exit_code:
                await self._exec(
                    "git",
                    "-C",
                    base,
                    "-c",
                    "core.hooksPath=/dev/null",
                    "worktree",
                    "add",
                    "--detach",
                    root,
                    commit,
                )
            borrowed = WorktreeSession(self.session, root, agent_id)

            def turns_used(turns: int) -> None:
                # One cumulative allowance per finding, including candidate revisions.
                self.records[finding_id]["turns"] = turns
                self._save()

            request = FixPreparationRequestV1(
                scan_id=self.scan_id,
                finding_id=finding_id,
                candidate=candidate,
                network_allowed=True,
                max_agent_turns=300,
            )
            environment = _RuntimeEnvironment(
                workspace=mirror,
                sandbox_session=borrowed,
                sandbox_workspace=root,
                base_commit=commit,
                initialized=True,
                execution_id=agent_id,
                coordinator=self.coordinator,
                parent_id=self.parent_id,
                turns_used=self.records[finding_id]["turns"],
                turn_sink=turns_used,
                scan_hooks=self.hooks,
                event_sink=self.event_sink,
                resume=resume,
                scan_context={
                    "assessment_source": self.source_roots[source],
                    "reproduction": report.get("poc_script_code", ""),
                },
            )
            result = await run_fix_preparation(
                request,
                mirror,
                sandbox_session=borrowed,
                runtime_environment=environment,
                artifact_path=artifact,
            )
            await self._emit(
                "finished", report, result, artifact if result.state == "ready" else None
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Fix task %s stopped", finding_id)
        finally:
            if started and result is None:
                with contextlib.suppress(Exception):
                    await self._emit("finished", report)
            if borrowed:
                with contextlib.suppress(Exception):
                    await borrowed.pty_terminate_all()
            if base:
                with contextlib.suppress(Exception):
                    await self._exec("git", "-C", base, "worktree", "remove", "--force", root)
            with contextlib.suppress(Exception):
                await self.coordinator.set_status(agent_id, "completed")
            record = self.records[finding_id]
            if record.get("digest") == digest and record.get("status") != "obsolete":
                record["status"] = "done" if result and result.state == "ready" else "stopped"
                if record["status"] == "done":
                    record["artifact"] = str(artifact)
                self._save()
            # Successful artifacts survive; unfinished source never becomes a deliverable.
            shutil.rmtree(directory / "source", ignore_errors=True)
            if result is None or result.state != "ready":
                artifact.unlink(missing_ok=True)

    async def wait(self) -> None:
        await asyncio.sleep(0)  # Drain report callbacks queued by worker threads.
        while pending := [task for task in self.tasks.values() if not task.done()]:
            await asyncio.gather(*pending, return_exceptions=True)
        self.closed = True

    async def close(self) -> None:
        self.closed = True
        for task in self.tasks.values():
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)


def _clone_revision(source: Path, mirror: Path, commit: str) -> None:
    subprocess.run(  # noqa: S603
        [
            shutil.which("git") or "/usr/bin/git",
            "clone",
            "--local",
            "--no-checkout",
            "--",
            str(source),
            str(mirror),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    subprocess.run(  # noqa: S603
        [
            shutil.which("git") or "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "checkout",
            "--detach",
            commit,
        ],
        cwd=mirror,
        check=True,
        capture_output=True,
        timeout=60,
    )

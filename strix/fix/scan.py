"""Persisted findings start Fix children through the native agent lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import json
import logging
import shutil
import subprocess
import time
from collections.abc import Awaitable, Callable
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from strix.fix.contracts import FixCandidateV1, FixPreparationRequestV1, FixPreparationResultV1
from strix.fix.prepare import PreparationContext
from strix.fix.runtime import (
    _finding_assignment,
    _FixHooks,
    _run_config,
    _RuntimeEnvironment,
    _untrusted_prompt_data,
    build_fix_agent,
    finish_native_fix,
)
from strix.fix.session import WorktreeSession
from strix.fix.workspace import git_metadata_archive
from strix.utils.secret_files import open_secret_file


logger = logging.getLogger(__name__)
FixSink = Callable[
    [str, dict[str, Any], FixPreparationResultV1 | None, Path | None], Awaitable[bool | None]
]


class ScanFixes:
    def __init__(
        self,
        *,
        session: Any,
        coordinator: Any,
        scan_id: str,
        state_dir: Path,
        local_sources: list[dict[str, Any]],
        hooks: Any,
        report_state: Any,
        event_sink: Any = None,
        sink: FixSink | None = None,
    ) -> None:
        self.session, self.coordinator = session, coordinator
        self.scan_id, self.directory = scan_id, state_dir / "fixes"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.path = self.directory / "tasks.json"
        self.records = json.loads(self.path.read_text()) if self.path.exists() else {}
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
        self.report_state = report_state
        self.tasks: dict[str, asyncio.Task[Any]] = {}
        self.dispatches: set[asyncio.Task[Any]] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.closed = False
        self.base = f"/workspace/.strix-fixes/{hashlib.sha256(scan_id.encode()).hexdigest()[:16]}"
        self._source_lock = asyncio.Lock()
        self._finding_locks: dict[str, asyncio.Lock] = {}
        self._staged: set[str] = set()

    def start(self, spawn: Any, parent_ctx: dict[str, Any]) -> None:
        self.loop = asyncio.get_running_loop()
        self._native_spawn, self._parent_ctx = spawn, parent_ctx
        self.report_state.finding_persisted_callback = self.notify
        for report in self.report_state.get_existing_vulnerabilities():
            self.notify(report)

    def notify(self, report: dict[str, Any]) -> None:
        if self.closed:
            return
        if self.loop is None:
            raise RuntimeError("Start the Fix dispatcher from its owning event loop first.")
        finding_id = str(report["id"])
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        if current is self.loop:
            self._schedule(finding_id)
        else:
            self.loop.call_soon_threadsafe(self._schedule, finding_id)

    def _schedule(self, finding_id: str) -> None:
        if self.closed:
            return
        task = asyncio.create_task(self._dispatch(finding_id))
        self.dispatches.add(task)
        task.add_done_callback(self.dispatches.discard)

    async def _reconcile(self) -> None:
        pending = []
        for report in self.report_state.get_existing_vulnerabilities():
            finding_id = str(report["id"])
            try:
                _, candidate = self._finding(finding_id)
            except ValueError:
                continue
            previous = self.records.get(finding_id, {})
            running = self.tasks.get(finding_id)
            if previous.get("digest") == candidate.digest() and (
                previous.get("status") in {"done", "stopped", "failed"}
                or (running and not running.done())
            ):
                continue
            pending.append(self._dispatch(finding_id))
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _dispatch(self, finding_id: str) -> None:
        try:
            report, _ = self._finding(finding_id)
            parent_id = report.get("agent_id") or self._parent_ctx["agent_id"]
            await self.spawn(
                finding_id,
                self._native_spawn,
                parent_ctx={**self._parent_ctx, "agent_id": parent_id},
                name=f"Fix: {report.get('title', finding_id)}",
                task="Implement and validate the saved finding in your assigned worktree.",
                skills=[],
                parent_history=[],
            )
        except Exception as error:  # noqa: BLE001 - report launch failure to the scan
            active = self.tasks.get(finding_id)
            if active and not active.done():
                active.cancel()
                await asyncio.gather(active, return_exceptions=True)
            logger.warning("fix.dispatch finding=%s rejected=%s", finding_id, error)
            await self.coordinator.send(
                self._parent_ctx["agent_id"],
                {
                    "from": "fix-runtime",
                    "type": "information",
                    "priority": "normal",
                    "content": (
                        f"Fix for {finding_id} was not started: {error}. "
                        "Do not create a replacement scan child to repair it."
                    ),
                },
            )

    def _save(self) -> None:
        temporary = self.path.with_suffix(".tmp")
        with open_secret_file(temporary) as stream:
            stream.write(json.dumps(self.records).encode())
        temporary.replace(self.path)

    def _finding(self, finding_id: str) -> tuple[dict[str, Any], FixCandidateV1]:
        report = next(
            (
                r
                for r in self.report_state.get_existing_vulnerabilities()
                if str(r.get("id")) == finding_id
            ),
            None,
        )
        if report is None:
            raise ValueError("Save the vulnerability report before requesting its Fix agent.")
        report = deepcopy(report)
        if not report.get("fix_candidate"):
            raise ValueError("The finding has no source-backed fix candidate.")
        candidate = FixCandidateV1.model_validate(report["fix_candidate"])
        if (
            report.get("validation_status") not in {None, "confirmed"}
            or not candidate.finding
            or candidate.finding.validation_status != "confirmed"
        ):
            raise ValueError("Only confirmed findings can start a Fix agent.")
        if candidate.blocker or not candidate.draft_edits or not candidate.source_identity:
            raise ValueError("The finding needs an unblocked source-backed fix candidate.")
        return report, candidate

    def _current(self, finding_id: str, digest: str) -> bool:
        try:
            return self._finding(finding_id)[1].digest() == digest
        except ValueError:
            return False

    async def _emit(
        self,
        stage: str,
        report: dict[str, Any],
        result: FixPreparationResultV1 | None = None,
        artifact: Path | None = None,
    ) -> bool:
        return self.sink is None or await self.sink(stage, report, result, artifact) is not False

    async def spawn(self, finding_id: str, spawn: Any, **kwargs: Any) -> dict[str, Any]:
        async with self._finding_locks.setdefault(finding_id, asyncio.Lock()):
            return await self._spawn(finding_id, spawn, **kwargs)

    async def _spawn(self, finding_id: str, spawn: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: PLR0915
        report, candidate = self._finding(finding_id)
        assert candidate.source_identity is not None
        digest = candidate.digest()
        previous = self.records.get(finding_id, {})
        running = self.tasks.get(finding_id)
        same = previous.get("digest") == digest
        if (
            same
            and previous.get("agent_id")
            and ((running and not running.done()) or previous.get("status") == "done")
        ):
            return {
                "success": True,
                "agent_id": previous["agent_id"],
                "status": previous["status"],
                "message": "This finding already has a Fix agent.",
            }
        retry = kwargs.pop("retry", False)
        if same and previous.get("status") in {"stopped", "failed"} and not retry:
            raise ValueError(
                previous.get("reason") or "The previous Fix attempt failed; it was not restarted."
            )
        if running and not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
        used = int(previous.get("turns", 0))
        if used >= 300:
            raise ValueError("This finding has exhausted its 300-turn Fix allowance.")
        if len(self.sources) != 1:
            raise ValueError("Fix requires one identified Git source checkout.")
        resume_id = (
            previous.get("agent_id") if same and previous.get("status") == "running" else None
        )
        key = hashlib.sha256(f"{finding_id}:{digest}".encode()).hexdigest()[:24]
        directory, root = self.directory / key, f"{self.base}/worktrees/{key}"
        artifact = directory / "prepared-fix.zip"
        borrowed, base, started = None, None, False
        source = self.sources[0]
        try:
            if not await self._emit("retrying" if retry and same else "started", report):
                raise ValueError(  # noqa: TRY301 - resource cleanup must surround setup
                    "The app declined this fix registration; check the current finding and attempt."
                )
            started = True
            directory.mkdir(parents=True, exist_ok=True)
            mirror = directory / "source"
            if not mirror.exists():
                await asyncio.to_thread(
                    _clone_revision, source, mirror, candidate.source_identity.value
                )
            base = await self._stage_base(source)
            exists = await self.session.exec("test", "-d", root, shell=False, timeout=30)
            if resume_id and exists.exit_code:
                raise ValueError(  # noqa: TRY301 - setup cleanup boundary
                    "The previous Fix worktree is unavailable; cannot safely resume."
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
                    candidate.source_identity.value,
                )
            borrowed = WorktreeSession(self.session, root, f"fix-{key}")
            request = FixPreparationRequestV1(
                scan_id=self.scan_id,
                finding_id=finding_id,
                candidate=candidate,
                network_allowed=True,
                max_agent_turns=300,
            )
            record = {
                "digest": digest,
                "turns": used,
                "status": "running",
                "parent_id": kwargs["parent_ctx"]["agent_id"],
                "name": kwargs["name"],
                "task": kwargs["task"],
            }
            self.records[finding_id] = record

            def turns_used(turns: int) -> None:
                record["turns"] = turns
                self._save()

            environment = _RuntimeEnvironment(
                workspace=mirror,
                sandbox_session=borrowed,
                sandbox_workspace=root,
                base_commit=candidate.source_identity.value,
                initialized=True,
                execution_id=f"fix-{key}",
                coordinator=self.coordinator,
                parent_id=record["parent_id"],
                turns_used=used,
                turn_sink=turns_used,
                scan_hooks=self.hooks,
                event_sink=self.event_sink,
                network_allowed=True,
                cancelled=lambda: not self._current(finding_id, digest),
            )
            environment.run_config_factory = lambda: _run_config(environment)
            hooks = _FixHooks(environment)
            started_at = time.monotonic()

            async def finished(result: Any, session: Any) -> None:
                prepared = None
                try:
                    prepared = await finish_native_fix(
                        request, environment, hooks, result, session, artifact
                    )
                    prepared.elapsed_seconds = time.monotonic() - started_at
                    delivered = await self._emit(
                        "finished",
                        report,
                        prepared,
                        artifact if prepared.state == "ready" else None,
                    )
                    if not delivered:
                        raise RuntimeError("The app declined the completed Fix result")  # noqa: TRY301
                    record["status"] = "done" if prepared.state == "ready" else "stopped"
                    record["reason"] = prepared.stop_reason
                    if prepared.state == "ready":
                        record["artifact"] = str(artifact)
                except Exception as error:
                    record["status"] = "stopped"
                    record["reason"] = str(error)
                    logger.exception("Fix completion delivery failed for %s", finding_id)
                    with contextlib.suppress(Exception):
                        await self._emit("finished", report)
                    raise
                finally:
                    self._save()
                    await self._cleanup(borrowed, base, root, directory)
                    if prepared is None or prepared.state != "ready":
                        artifact.unlink(missing_ok=True)

            parent_ctx = {
                **kwargs["parent_ctx"],
                "sandbox_session": borrowed,
                "before_agent_finish": hooks.before_finish,
            }
            assignment = _untrusted_prompt_data(
                {
                    "finding": _finding_assignment(PreparationContext(request, mirror, candidate)),
                    "scan_context": {
                        "assessment_source": self.source_roots[source],
                        "reproduction": report.get("poc_script_code", ""),
                    },
                }
            )
            spawned = await spawn(
                **{
                    **kwargs,
                    "parent_ctx": parent_ctx,
                    "task": kwargs["task"] + "\n\n" + assignment,
                    "skills": ["fix_task"],
                    "factory": lambda **kw: build_fix_agent(name=kw["name"], workspace_root=root),
                    "run_config": _run_config(environment),
                    "hooks": hooks,
                    "max_turns": 300 - used,
                    "on_complete": finished,
                    "child_id": resume_id,
                },
            )
            record["agent_id"] = spawned["agent_id"]
            self.tasks[finding_id] = self.coordinator.runtimes[spawned["agent_id"]].task
            self._save()
            return cast("dict[str, Any]", spawned)
        except BaseException as error:
            if started:
                with contextlib.suppress(Exception):
                    await self._emit("finished", report)
            await self._cleanup(borrowed, base, root, directory)
            if finding_id in self.records:
                self.records[finding_id]["status"] = "stopped"
                self.records[finding_id]["reason"] = str(error)
                self._save()
            raise

    async def _cleanup(self, borrowed: Any, base: str | None, root: str, directory: Path) -> None:
        if borrowed:
            with contextlib.suppress(Exception):
                await borrowed.pty_terminate_all()
        if base:
            with contextlib.suppress(Exception):
                await self._exec("git", "-C", base, "worktree", "remove", "--force", root)
        shutil.rmtree(directory / "source", ignore_errors=True)

    async def wait(self) -> None:
        await asyncio.gather(*self.dispatches, return_exceptions=True)
        await self._reconcile()
        self.closed = True
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)

    async def close(self) -> None:
        self.closed = True
        for task in self.dispatches:
            task.cancel()
        await asyncio.gather(*self.dispatches, return_exceptions=True)
        for task in self.tasks.values():
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)

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

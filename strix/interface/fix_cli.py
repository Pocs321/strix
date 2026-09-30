"""Local CLI for the same OSS fix workflow used by hosted callers."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import uuid
import zipfile
from pathlib import Path
from typing import Any, cast

from rich.console import Console

from strix.config import load_settings
from strix.config.models import configure_sdk_model_defaults
from strix.core.paths import run_dir_for
from strix.fix import (
    FixCandidateV1,
    FixPreparationRequestV1,
    FixPreparationResultV1,
    PreparationState,
)
from strix.fix.runtime import run_isolated_fix_preparation
from strix.interface.environment import check_docker_installed, pull_docker_image
from strix.interface.scan_setup import preflight_model_connection


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="strix fix", description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--finding", type=Path, help="Saved finding or vulnerabilities.json.")
    inputs.add_argument("--request", type=Path, help="FixPreparationRequestV1 JSON (automation).")
    parser.add_argument("--finding-id", help="Finding ID to select from vulnerabilities.json.")
    parser.add_argument("--repo", "--workspace", dest="repo", type=Path, required=True)
    parser.add_argument(
        "--output", type=Path, help="Result JSON; defaults to a new strix_runs folder."
    )
    parser.add_argument(
        "--artifact", type=Path, help="Patch/log archive; defaults beside the result."
    )
    parser.add_argument("--max-agent-turns", type=int)
    parser.add_argument("--max-budget", type=float, help="Combined LLM cost budget in USD.")
    parser.add_argument("--timeout", type=int, help="Whole-job timeout in seconds.")
    return parser


def _load_request(args: argparse.Namespace) -> FixPreparationRequestV1:
    if args.request:
        request = FixPreparationRequestV1.model_validate_json(args.request.read_text())
    else:
        data: Any = json.loads(args.finding.read_text())
        if isinstance(data, list):
            records = [
                cast("dict[str, Any]", row)
                for row in cast("list[object]", data)
                if isinstance(row, dict)
            ]
            matches = [f for f in records if f.get("id") == args.finding_id]
            if not args.finding_id or len(matches) != 1:
                raise ValueError("Use --finding-id to select exactly one saved finding.")
            data = matches[0]
        if not isinstance(data, dict):
            raise ValueError("The finding must be a JSON object.")
        finding = cast("dict[str, Any]", data)
        raw = finding.get("fix_candidate")
        candidate = FixCandidateV1.model_validate(raw if raw is not None else finding)
        if candidate.source_identity is None:
            raise ValueError(
                "The finding needs fix_candidate.source_identity from its source scan."
            )
        request = FixPreparationRequestV1(
            scan_id=str(finding.get("scan_id") or "local"),
            finding_id=str(finding.get("id") or args.finding_id or uuid.uuid4().hex),
            candidate=candidate,
            network_allowed=True,
        )
    if (
        request.candidate.source_identity is None
        or request.candidate.source_identity.kind != "commit"
    ):
        raise ValueError("Local fix preparation requires a finding tied to a Git commit.")
    overrides = {
        key: value
        for key, value in {
            "max_agent_turns": args.max_agent_turns,
            "max_budget_usd": args.max_budget,
            "timeout_seconds": args.timeout,
        }.items()
        if value is not None
    }
    return FixPreparationRequestV1.model_validate({**request.model_dump(), **overrides})


async def _preflight() -> None:
    settings = load_settings()
    if not settings.llm.model:
        raise ValueError("Configure STRIX_LLM before preparing a fix.")
    configure_sdk_model_defaults(settings)
    if settings.runtime.backend == "docker":
        check_docker_installed()
        pull_docker_image()
    await preflight_model_connection(settings.llm.model, settings=settings)


def _summary(result: FixPreparationResultV1) -> str:
    lines = ["# Fix preparation", "", f"Status: {result.state.value}", "", result.stop_reason]
    if result.verifier:
        lines.extend(["", "## Review", "", result.verifier.summary])
    elif result.attempt_history:
        lines.extend(["", "## Repair", "", result.attempt_history[-1].repair.summary])
    lines.extend(["", "## Recorded commands", "", "Includes diagnostic and superseded attempts."])
    lines.extend(
        f"- {check.name}: {check.status.value}; exit code {check.exit_code}."
        for check in result.checks
    )
    gaps = result.gaps.copy()
    if result.verifier:
        gaps.extend(result.verifier.gaps)
    if result.blocker:
        gaps.append(result.blocker.user_action)
    if gaps:
        lines.extend(["", "## Remaining work", "", *dict.fromkeys(gaps)])
    return "\n".join(lines) + "\n"


async def _execute(
    request: FixPreparationRequestV1, repo: Path, output: Path, artifact: Path
) -> FixPreparationResultV1:
    await _preflight()
    result = await run_isolated_fix_preparation(request, repo, artifact_path=artifact)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    output.with_suffix(".md").write_text(_summary(result), encoding="utf-8")
    with zipfile.ZipFile(artifact) as archive:
        output.with_suffix(".patch").write_bytes(archive.read("changes.patch"))
    return result


def run_fix(argv: list[str]) -> int:
    """Return 0 approved, 2 incomplete, 1 startup failure, or 130 interrupted."""
    args = _parser().parse_args(argv)
    console = Console()
    try:
        request = _load_request(args)
        output = (
            args.output or run_dir_for(f"fix-{uuid.uuid4().hex[:12]}") / "result.json"
        ).resolve()
        artifact = (args.artifact or output.with_suffix(".zip")).resolve()
        # Result files must not overwrite source or a previous preparation's evidence.
        paths = [output, artifact, output.with_suffix(".md"), output.with_suffix(".patch")]
        if len(set(paths)) != len(paths) or any(path.exists() for path in paths):
            console.print("Choose new, distinct output paths for this preparation.")
            return 1
        result = asyncio.run(_execute(request, args.repo.resolve(), output, artifact))
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("Fix preparation interrupted. Any saved work is in the patch/log archive.")
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        console.print(f"Fix preparation failed: {exc}", markup=False)
        return 1
    console.print(f"{result.state.value}: {result.stop_reason}", markup=False)
    console.print(
        f"Review: {output.with_suffix('.md')}\nPatch: {output.with_suffix('.patch')}", markup=False
    )
    console.print(f"Result: {output}\nArchive: {artifact}", markup=False)
    return 0 if result.state is PreparationState.READY else 2


if __name__ == "__main__":
    import sys

    sys.exit(run_fix(sys.argv[1:]))

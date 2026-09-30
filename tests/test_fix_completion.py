"""Real Strix loop + SDK shell/filesystem + customer tests, with scripted inference."""

from __future__ import annotations

import json
import shlex
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
from agents import Model, RunConfig
from agents.items import ModelResponse
from agents.sandbox import SandboxRunConfig
from agents.tool import CustomTool
from agents.usage import Usage
from openai.types.responses import (
    ResponseCustomToolCall,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from strix.config.models import _completed_stream_event
from strix.fix import PreparationState
from strix.fix import runtime as fix_runtime
from strix.interface.fix_cli import _summary
from tests.test_fix_reliability import environment, existing_suite
from tests.test_fix_runtime import _request, _workspace


def call(name: str, **arguments: Any) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        type="function_call", name=name, call_id=name, arguments=json.dumps(arguments)
    )


def finish(outcome: str, summary: str = "Fix and validation results reviewed.") -> Any:
    return call("agent_finish", outcome=outcome, result_summary=summary)


def shell(cmd: str) -> Any:
    return call("exec_command", cmd=cmd, login=False, yield_time_ms=10000)


def patch(value: str = "safe") -> list[Any]:
    production = "def result():\n    return " + repr(value) + "\n"
    regression = (
        "import unittest\nfrom app import result\nclass Security(unittest.TestCase):\n"
        "    def test_safe(self): self.assertEqual(result(),'safe')\n"
    )
    return [
        shell(f"printf %s {shlex.quote(production)} > app.py"),
        shell(f"printf %s {shlex.quote(regression)} > tests/test_security.py"),
    ]


def suite_commands() -> list[Any]:
    python = shlex.quote(sys.executable)
    return [
        shell(f"{python} -m unittest discover -s tests -p test_existing.py"),
        shell(f"{python} -m unittest discover -s tests -p test_security.py"),
    ]


class ScriptedModel(Model):
    def __init__(self, repair: list[Any], review: list[Any]) -> None:
        self.responses = {"repair": repair, "review": review}
        self.inputs: dict[str, list[Any]] = {"repair": [], "review": []}
        self.tools: set[str] = set()

    async def get_response(self, **kwargs: Any) -> ModelResponse:
        role = "review" if "Independently review" in kwargs["system_instructions"] else "repair"
        self.inputs[role].append(list(kwargs["input"]))
        self.tools.update(t.name for t in kwargs["tools"])
        assert self.responses[role], f"Unexpected additional {role} turn"
        item = self.responses[role].pop(0)
        if isinstance(item, str):
            item = ResponseOutputMessage(
                id=f"msg-{role}-{len(self.inputs[role])}",
                type="message",
                role="assistant",
                status="completed",
                content=[ResponseOutputText(type="output_text", text=item, annotations=[])],
            )
        else:
            arguments = json.loads(item.arguments)
            item = item.model_copy(
                update={
                    "call_id": f"{role}-{len(self.inputs[role])}",
                    "arguments": json.dumps(arguments),
                }
            )
            if item.name == "apply_patch" and any(
                isinstance(t, CustomTool) and t.name == item.name for t in kwargs["tools"]
            ):
                item = ResponseCustomToolCall(
                    type="custom_tool_call",
                    name=item.name,
                    call_id=item.call_id,
                    input=arguments["patch"],
                )
        return ModelResponse(output=[item], usage=Usage(requests=1), response_id=None)

    async def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.update(
            zip(
                [
                    "system_instructions",
                    "input",
                    "model_settings",
                    "tools",
                    "output_schema",
                    "handoffs",
                    "tracing",
                ],
                args,
                strict=False,
            )
        )
        yield _completed_stream_event(await self.get_response(**kwargs), "scripted")


async def scenario(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    model: ScriptedModel,
    turns: int = 30,
    *,
    repair_turns: int | None = None,
    review_turns: int | None = None,
) -> tuple[Any, Any]:
    workspace, _ = _workspace(tmp_path)
    commit = existing_suite(workspace)
    env = environment(workspace, tmp_path)
    monkeypatch.setattr(
        fix_runtime,
        "_run_config",
        lambda env: RunConfig(
            model=model, sandbox=SandboxRunConfig(session=env.session), tracing_disabled=True
        ),
    )
    request = _request(commit)
    request.max_agent_turns = turns
    request.max_repair_turns = repair_turns
    request.max_review_turns = review_turns
    result = await fix_runtime.run_fix_preparation(
        request,
        workspace,
        sandbox_session=env.session,
        runtime_environment=env,
        artifact_path=tmp_path / "prepared.zip",
    )
    return result, env


@pytest.mark.asyncio
async def test_native_agents_review_executes_customer_and_regression_tests(tmp_path, monkeypatch):
    model = ScriptedModel([*patch(), finish("done")], [*suite_commands(), finish("approved")])
    result, env = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert result.attempts == 1
    assert {"exec_command", "apply_patch", "agent_finish"} <= model.tools
    assert not {"create_agent", "finish_scan", "record_coverage", "run_command"} & model.tools
    assert len(result.checks) == 4
    assert all(c.exit_code == 0 for c in result.checks)
    assert all("Ran 1 test" in c.output for c in result.checks[-2:])
    assert result.prepared_source_digest == result.verifier.source_digest == env.validated_digest
    assert (tmp_path / "fix-agents.db").exists()
    with zipfile.ZipFile(tmp_path / "prepared.zip") as archive:
        assert "files/tests/test_security.py" in archive.namelist()
        assert len(json.loads(archive.read("execution.json"))) == 4
        sessions = json.loads(archive.read("agent-sessions.json"))
        assert sessions["repair"]
        assert sessions["review"]
        assert b"agent_finish" in archive.read("tool-results.jsonl")


@pytest.mark.asyncio
async def test_reviewer_corrections_are_validated_and_delivered(tmp_path, monkeypatch):
    model = ScriptedModel(
        [*patch("incorrect"), finish("done")],
        [
            *suite_commands(),
            *patch(),
            *suite_commands(),
            finish("approved", "Corrected patch; both suites now pass."),
        ],
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert any(c.exit_code == 1 for c in result.checks)
    assert all(c.exit_code == 0 for c in result.checks[-2:])
    assert result.prepared_source_digest != result.attempt_history[0].repair.source_digest
    with zipfile.ZipFile(tmp_path / "prepared.zip") as archive:
        assert b"return 'safe'" in archive.read("files/app.py")


@pytest.mark.asyncio
async def test_review_feedback_resumes_both_sessions(tmp_path, monkeypatch):
    model = ScriptedModel(
        [*patch("incorrect"), finish("done"), *patch(), finish("done")],
        [
            *suite_commands(),
            finish("changes_requested", "The regression fails: return the safe value."),
            *suite_commands(),
            finish("approved"),
        ],
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert result.attempts == 2
    assert "The regression fails" in json.dumps(model.inputs["repair"][-1])
    assert "changes_requested" in json.dumps(model.inputs["review"][-1])


@pytest.mark.asyncio
async def test_invalid_finish_outcome_is_corrected_through_native_tool(tmp_path, monkeypatch):
    model = ScriptedModel(
        [*patch(), finish("approved"), finish("done")], [*suite_commands(), finish("approved")]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert "Choose an outcome" in json.dumps(model.inputs["repair"][-1])


@pytest.mark.asyncio
async def test_missing_finish_summary_is_corrected_without_crashing(tmp_path, monkeypatch):
    model = ScriptedModel(
        [*patch(), call("agent_finish", outcome="done"), finish("done")],
        [*suite_commands(), call("agent_finish", outcome="approved"), finish("approved")],
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    for role in ("repair", "review"):
        error = json.dumps(model.inputs[role][-1])
        assert "result_summary" in error and "Field required" in error
    with zipfile.ZipFile(tmp_path / "prepared.zip") as archive:
        assert b"Field required" in archive.read("tool-results.jsonl")


@pytest.mark.asyncio
async def test_completion_limitations_and_recommendations_survive_approval(tmp_path, monkeypatch):
    limitation = "Production integration still requires customer credentials."
    note = "Consider wider integration coverage."
    model = ScriptedModel(
        [
            *patch(),
            call(
                "agent_finish",
                outcome="done",
                result_summary="Patch ready.",
                open_items=["Reviewer must run existing tests."],
                final_recommendations=["Repair follow-up."],
            ),
        ],
        [
            *suite_commands(),
            call(
                "agent_finish",
                outcome="approved",
                result_summary="Tests passed.",
                open_items=[limitation],
                final_recommendations=[note],
            ),
        ],
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY
    assert result.verifier.gaps == result.gaps == [limitation]
    assert result.verifier.notes == [note]
    assert result.attempt_history[0].repair.notes == ["Repair follow-up."]
    assert "Reviewer must run existing tests." in json.dumps(model.inputs["review"][0])
    assert limitation in _summary(result)
    assert note in _summary(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("limited_role", ["repair", "review"])
async def test_role_budget_is_cumulative_across_feedback(tmp_path, monkeypatch, limited_role):
    model = ScriptedModel(
        [*patch("incorrect"), finish("done"), *patch(), finish("done")],
        [
            *suite_commands(),
            finish("changes_requested", "Correct the return value."),
            *suite_commands(),
            finish("approved"),
        ],
    )
    result, _ = await scenario(
        tmp_path,
        monkeypatch,
        model,
        repair_turns=5 if limited_role == "repair" else 20,
        review_turns=4 if limited_role == "review" else 20,
    )
    assert result.state is PreparationState.BLOCKED
    assert result.attempts == 2
    assert "budget" in result.stop_reason
    assert len(model.inputs[limited_role]) == (5 if limited_role == "repair" else 4)
    assert model.responses[limited_role]  # The budget stopped execution, not a scripted completion.
    resumed_input = json.dumps(model.inputs[limited_role][3])
    assert (
        f"4/{5 if limited_role == 'repair' else 4} turns used across all handoffs" in resumed_input
    )
    assert "in-progress work is discarded" not in resumed_input
    assert result.final_file_manifest


@pytest.mark.asyncio
async def test_blocked_tests_keep_patch_without_reopening_repair(tmp_path, monkeypatch):
    model = ScriptedModel(
        [*patch(), finish("done")],
        [
            shell("exit 1"),
            finish("blocked", "Customer unit tests require an unavailable database."),
        ],
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.BLOCKED
    assert result.attempts == 1
    assert result.final_file_manifest
    assert result.checks[-1].exit_code == 1


@pytest.mark.asyncio
async def test_budget_interruption_saves_partial_patch(tmp_path, monkeypatch):
    model = ScriptedModel([*patch(), shell("pwd")], [])
    result, _ = await scenario(tmp_path, monkeypatch, model, turns=2)
    assert result.state is PreparationState.BLOCKED, result.model_dump_json()
    assert result.final_file_manifest
    assert result.verifier is None
    assert "budget" in result.stop_reason.lower()


@pytest.mark.asyncio
async def test_plain_prose_uses_native_lifecycle_recovery(tmp_path, monkeypatch):
    model = ScriptedModel(
        [*patch(), "All done", finish("done")], [*suite_commands(), finish("approved")]
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert "lifecycle tool" in json.dumps(model.inputs["repair"][-1])


@pytest.mark.asyncio
async def test_patch_changed_after_approval_is_not_delivered_as_ready(tmp_path, monkeypatch):
    original = fix_runtime._FixHooks.on_tool_end

    async def change_after_finish(hooks, context, agent, tool, result):
        await original(hooks, context, agent, tool, result)
        if hooks.completion_digest:
            (Path(hooks.environment.sandbox_workspace) / "app.py").write_text(
                "def result():\n    return 'changed after approval'\n"
            )

    monkeypatch.setattr(fix_runtime._FixHooks, "on_tool_end", change_after_finish)
    model = ScriptedModel([*patch(), finish("done")], [*suite_commands(), finish("approved")])
    result, env = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.BLOCKED, result.model_dump_json()
    assert "changed after review" in result.stop_reason
    assert result.verifier.source_digest != env.validated_digest


@pytest.mark.asyncio
@pytest.mark.parametrize("chat_tools", [True, False])
async def test_native_filesystem_patch_is_shared_with_reviewer(tmp_path, monkeypatch, chat_tools):
    monkeypatch.setattr(fix_runtime, "uses_chat_completions_tool_schema", lambda *_: chat_tools)
    production_patch = (
        "*** Begin Patch\n*** Update File: app.py\n@@\n"
        "-    return 'unsafe'\n+    return 'safe'\n*** End Patch"
    )
    model = ScriptedModel(
        [call("apply_patch", patch=production_patch), patch()[1], finish("done")],
        [*suite_commands(), finish("approved")],
    )
    result, _ = await scenario(tmp_path, monkeypatch, model)
    assert result.state is PreparationState.READY, result.model_dump_json()
    assert all(c.exit_code == 0 for c in result.checks)

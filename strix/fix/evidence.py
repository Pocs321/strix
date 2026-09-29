"""Execution facts shared by local and managed fix preparation."""

from __future__ import annotations

import re
from typing import Literal

from strix.fix.contracts import CheckResult, CheckStatus, CommandSpec


def passed_test_count(output: str) -> int | None:  # noqa: PLR0911 - native summary formats
    """Recognize native test-runner summaries, not the model's account of a run.

    Counts are optional: runners use different output formats. This is execution
    evidence, not an assertion that a test covers the finding; the reviewer checks that.
    """
    plain = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", output)
    if command_status(0, plain)[0] is CheckStatus.SKIPPED:
        return 0
    counts = re.findall(r"\b(\d+)\s+(?:passed|pass)\b", plain, re.IGNORECASE)
    counts += re.findall(r"(?:#|\u2139)\s+pass\s+(\d+)\b", plain)
    if counts:
        return max(int(count) for count in counts)
    unittest = re.search(r"Ran (\d+) tests? in [^\n]+\n\s*OK(?: \(skipped=(\d+)\))?", plain)
    if unittest:
        return max(0, int(unittest[1]) - int(unittest[2] or 0))
    rspec = re.search(r"(\d+) examples?, (\d+) failures?(?:, (\d+) pending)?", plain)
    if rspec:
        return max(0, int(rspec[1]) - int(rspec[2]) - int(rspec[3] or 0))
    minitest = re.search(
        r"(\d+) runs, \d+ assertions, (\d+) failures, (\d+) errors, (\d+) skips", plain
    )
    if minitest:
        return max(0, int(minitest[1]) - sum(int(minitest[i]) for i in (2, 3, 4)))
    if re.search(r"^(?:=+\s*)?[1-9]\d* skipped(?:\s+in [^\n=]+)?(?:\s*=+)?$", plain, re.MULTILINE):
        return 0
    go = re.findall(r"^\s*--- PASS: ", plain, re.MULTILINE)
    return len(go) if go else None


def record_test_execution(result: CheckResult, command: CommandSpec) -> CheckResult:
    """Known empty/skipped runs cannot pass; unknown summary formats go to review."""
    count = passed_test_count(result.output) if command.purpose != "quality" else None
    update: dict[str, object] = {
        "purpose": command.purpose,
        "tests_passed": count,
        "required": command.required,
        "name": command.name,
        "argv": command.argv,
        "cwd": command.cwd,
    }
    if command.purpose != "quality" and result.status is CheckStatus.PASSED and count == 0:
        update.update(
            status=CheckStatus.SKIPPED,
            output=result.output + "\nThe runner reported no passing tests.",
        )
    return result.model_copy(update=update)


def command_status(
    exit_code: int, output: str
) -> tuple[CheckStatus, Literal["environment", "check", "harness", "unknown"] | None]:
    """Classify launch/collection failures before interpreting an assertion result."""
    if exit_code in {126, 127} or (
        exit_code != 0
        and re.search(
            r"(?:command not found|exec: \S+: not found)",
            output,
            re.IGNORECASE,
        )
    ):
        return CheckStatus.UNAVAILABLE, "environment"
    if exit_code != 0 and re.search(
        r"(?:SyntaxError|ReferenceError: require is not defined)", output
    ):
        return CheckStatus.FAILED, "unknown"
    if exit_code != 0 and re.search(
        r"(?:No module named |Cannot find module |ERR_MODULE_NOT_FOUND|"
        r"ECONNREFUSED|Could not connect to server)",
        output,
        re.IGNORECASE,
    ):
        # An incorrect import or a failed service is not evidence that installing
        # dependencies is appropriate. Return it to the caller for diagnosis.
        return CheckStatus.FAILED, "unknown"
    if re.search(
        r"(?:Skipping to avoid parser lock|collected 0 items|"
        r"No test files found|No tests found, exiting with code 0)",
        output,
        re.IGNORECASE,
    ):
        return CheckStatus.SKIPPED, None
    return (CheckStatus.PASSED, None) if exit_code == 0 else (CheckStatus.FAILED, "check")

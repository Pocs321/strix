"""Execution facts shared by local and managed fix preparation."""

from __future__ import annotations

import re
from typing import Literal

from strix.fix.contracts import CheckStatus


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

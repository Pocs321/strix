"""Execution facts shared by local and managed fix preparation."""

from __future__ import annotations

import re
from typing import Literal

from strix.fix.contracts import CheckStatus


def command_status(
    exit_code: int, output: str
) -> tuple[CheckStatus, Literal["environment", "check"] | None]:
    """Classify launch/collection failures before interpreting an assertion result."""
    if exit_code in {126, 127} or (
        exit_code != 0
        and re.search(
            r"(?:command not found|exec: \S+: not found|No module named |"
            r"Cannot find module |ECONNREFUSED|Could not connect to server)",
            output,
            re.IGNORECASE,
        )
    ):
        return CheckStatus.UNAVAILABLE, "environment"
    if re.search(
        r"(?:Skipping to avoid parser lock|collected 0 items|"
        r"No test files found|No tests found, exiting with code 0)",
        output,
        re.IGNORECASE,
    ):
        return CheckStatus.SKIPPED, None
    return (CheckStatus.PASSED, None) if exit_code == 0 else (CheckStatus.FAILED, "check")

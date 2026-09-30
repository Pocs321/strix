"""Emit the MCP connection configs that point Strix at the Strix 2 wrapper servers.

Strix connects to the MCP servers listed in ``~/.strix/mcp-servers.json`` (or a file
named by ``--mcp-config`` / ``$STRIX_MCP_CONFIG``). This module builds the
:class:`~strix.tools.mcp.config.McpConnectionConfig` entries for the host-side
wrappers so an operator (or a future auto-wire hook) can register them without
hand-writing JSON, each launched as ``<python> -m strix.mcp_servers.<name>`` with a
tight ``allowed_tools`` allowlist.

Scope config is passed through to the subprocess so the wrapper enforces the same
authorized scope as the parent run: ``STRIX_SCOPE_CONFIG`` and
``STRIX_ALLOW_INTRUSIVE`` are forwarded from the current environment when set. The
subprocess otherwise inherits AWS credential resolution from the host environment
and shared config.
"""

from __future__ import annotations

import os
import sys

from strix.mcp_servers import aws
from strix.tools.mcp.config import McpConnectionConfig


# Environment variables forwarded from the parent into every wrapper subprocess so
# it resolves and enforces the same authorized scope. Credentials are NOT listed
# here: boto3 picks those up from the inherited host environment / shared config.
_SCOPE_ENV_PASSTHROUGH = ("STRIX_SCOPE_CONFIG", "STRIX_ALLOW_INTRUSIVE")


def _passthrough_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {key: os.environ[key] for key in _SCOPE_ENV_PASSTHROUGH if os.environ.get(key)}
    if extra:
        env.update(extra)
    return env


def aws_wrapper_config(
    *,
    python_executable: str | None = None,
    region: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> McpConnectionConfig:
    """Build the connection config for the read-only AWS wrapper.

    Args:
        python_executable: Interpreter to launch the server with; defaults to the
            current one so the subprocess shares this venv (and thus boto3 + strix).
        region: Optional default AWS region, forwarded as ``AWS_DEFAULT_REGION``.
        extra_env: Extra environment variables for the subprocess.
    """
    env = _passthrough_env(extra_env)
    if region:
        env.setdefault("AWS_DEFAULT_REGION", region)
    return McpConnectionConfig(
        name="strix-aws",
        transport="stdio",
        command=python_executable or sys.executable,
        args=["-m", "strix.mcp_servers.aws"],
        env=env,
        allowed_tools=list(aws.TOOL_NAMES),
        active_tools=list(aws.TOOL_NAMES),
        notes=(
            "Host-side AWS read-only checks (STS identity, S3 recon + bounded object "
            "read), scope-gated on cloud.aws_account_ids and fail-closed without a "
            "scope.yaml. Credentials stay on the host. Read-only: use results to file "
            "candidates (s3_get_bucket_public_status) and validated findings "
            "(s3_get_object_head)."
        ),
        session_timeout_seconds=120.0,
    )


def builtin_wrapper_configs() -> list[McpConnectionConfig]:
    """Return every host-side wrapper Strix 2 ships (currently the AWS wrapper)."""
    return [aws_wrapper_config()]

"""Tests for the read-only AWS MCP wrapper and its connection config.

No real AWS: a fake client factory is injected so tools exercise the scope gating,
argument handling, and evidence shaping without credentials or network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest
from botocore.exceptions import ClientError

from strix.mcp_servers import aws
from strix.mcp_servers.base import ScopeGuard
from strix.mcp_servers.registry import (
    applicable_builtin_configs,
    aws_wrapper_config,
    builtin_wrapper_configs,
    configs_with_builtins,
)
from strix.scope.enforcement import get_active_policy, set_active_policy
from strix.scope.schema import ScopePolicy
from strix.tools.mcp.config import McpConnectionConfig


if TYPE_CHECKING:
    from collections.abc import Iterator

_ACCOUNT = "123456789012"
_ARN = "arn:aws:iam::123456789012:user/pentester"
_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"


class _FakeBody:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def read(self, amt: int | None = None) -> bytes:
        return self._content if amt is None else self._content[:amt]


class _FakeSTS:
    def __init__(self, identity: dict[str, Any]) -> None:
        self._identity = identity

    def get_caller_identity(self) -> dict[str, Any]:
        return self._identity


class _FakeS3:
    def __init__(self, *, obj: bytes = b"", public_acl: bool = False) -> None:
        self._obj = obj
        self._public_acl = public_acl

    def list_buckets(self) -> dict[str, Any]:
        return {"Buckets": [{"Name": "secret-bucket"}, {"Name": "logs"}]}

    def get_public_access_block(self, **_: Any) -> dict[str, Any]:
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}

    def get_bucket_acl(self, **_: Any) -> dict[str, Any]:
        grants: list[dict[str, Any]] = []
        if self._public_acl:
            grants.append(
                {"Grantee": {"Type": "Group", "URI": _ALL_USERS}, "Permission": "READ"}
            )
        return {"Grants": grants}

    def get_bucket_policy_status(self, **_: Any) -> dict[str, Any]:
        return {"PolicyStatus": {"IsPublic": False}}

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.last_range = kwargs.get("Range")
        return {
            "Body": _FakeBody(self._obj),
            "ContentType": "text/plain",
            "ContentLength": len(self._obj),
            "ContentRange": f"bytes 0-{len(self._obj) - 1}/{len(self._obj)}",
            "ETag": '"abc"',
        }


def _factory(*, sts: _FakeSTS | None = None, s3: _FakeS3 | None = None) -> Any:
    sts = sts or _FakeSTS({"Account": _ACCOUNT, "Arn": _ARN, "UserId": "AIDA"})
    s3 = s3 or _FakeS3()

    def factory(service: str, _region: str | None) -> Any:
        if service == "sts":
            return sts
        if service == "s3":
            return s3
        raise AssertionError(f"unexpected service {service!r}")

    return factory


def _policy(**overrides: object) -> ScopePolicy:
    base: dict[str, object] = {"cloud": {"aws_account_ids": [_ACCOUNT]}}
    base.update(overrides)
    return ScopePolicy.model_validate(base)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    saved = get_active_policy()
    aws.reset_state()
    aws.set_client_factory(_factory())
    # A plain guard reads the active policy live; avoids reloading scope.yaml from disk.
    monkeypatch.setattr(aws, "_guard", ScopeGuard)
    try:
        yield
    finally:
        aws.reset_state()
        aws.set_client_factory(None)
        set_active_policy(saved)


# --- scope gating ------------------------------------------------------------

def test_whoami_refused_without_scope() -> None:
    set_active_policy(None)
    body = json.loads(aws.aws_whoami())
    assert body["success"] is False
    assert body["refused"] == "no_scope"


def test_whoami_in_scope() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.aws_whoami())
    assert body["success"] is True
    assert body["account"] == _ACCOUNT
    assert body["arn"] == _ARN


def test_whoami_out_of_scope_account() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    body = json.loads(aws.aws_whoami())
    assert body["success"] is False
    assert body["refused"] == "out_of_scope"


def test_identity_error_is_reported() -> None:
    class _Boom(_FakeSTS):
        def get_caller_identity(self) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetCallerIdentity")

    set_active_policy(_policy())
    aws.set_client_factory(_factory(sts=_Boom({})))
    body = json.loads(aws.aws_whoami())
    assert body["success"] is False
    assert "caller identity" in body["error"]


# --- s3 recon ----------------------------------------------------------------

def test_list_buckets() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.s3_list_buckets())
    assert body["success"] is True
    assert body["bucket_count"] == 2
    assert "secret-bucket" in body["buckets"]


def test_bucket_public_status_flags_public_acl() -> None:
    set_active_policy(_policy())
    aws.set_client_factory(_factory(s3=_FakeS3(public_acl=True)))
    body = json.loads(aws.s3_get_bucket_public_status("secret-bucket"))
    assert body["success"] is True
    assert body["looks_public"] is True
    assert any("AllUsers" in g for g in body["signals"]["acl_public_grants"])


def test_bucket_public_status_private_bucket() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.s3_get_bucket_public_status("logs"))
    assert body["success"] is True
    assert body["looks_public"] is False


# --- s3 bounded read evidence ------------------------------------------------

def test_get_object_head_captures_bounded_evidence() -> None:
    set_active_policy(_policy())
    content = b"TOP SECRET credentials: hunter2"
    aws.set_client_factory(_factory(s3=_FakeS3(obj=content)))
    body = json.loads(aws.s3_get_object_head("secret-bucket", "creds.txt", max_bytes=8))
    assert body["success"] is True
    assert body["bytes_captured"] == 8
    head = content[:8]
    assert base64.b64decode(body["body_head_base64"]) == head
    assert body["sha256"] == hashlib.sha256(head).hexdigest()
    assert body["principal_arn"] == _ARN
    assert body["request"]["range"] == "bytes=0-7"


def test_get_object_head_clamps_to_1024_bytes() -> None:
    set_active_policy(_policy())
    aws.set_client_factory(_factory(s3=_FakeS3(obj=b"x" * 5000)))
    body = json.loads(aws.s3_get_object_head("b", "k", max_bytes=5000))
    assert body["bytes_captured"] == 1024
    assert body["request"]["range"] == "bytes=0-1023"


def test_get_object_head_refused_out_of_scope() -> None:
    set_active_policy(_policy(cloud={"aws_account_ids": ["999999999999"]}))
    body = json.loads(aws.s3_get_object_head("b", "k"))
    assert body["success"] is False
    assert body["refused"] == "out_of_scope"


def test_get_object_head_requires_bucket_and_key() -> None:
    set_active_policy(_policy())
    body = json.loads(aws.s3_get_object_head("", ""))
    assert body["success"] is False


# --- server + config ---------------------------------------------------------

async def test_build_registers_only_allowlisted_tools() -> None:
    server = aws.build()
    assert server.name == "strix-aws"
    tools = await server.list_tools()
    assert {t.name for t in tools} == set(aws.TOOL_NAMES)


def test_aws_wrapper_config_shape() -> None:
    config = aws_wrapper_config()
    assert config.name == "strix-aws"
    assert config.transport == "stdio"
    assert config.command == sys.executable
    assert config.args == ["-m", "strix.mcp_servers.aws"]
    assert config.allowed_tools == list(aws.TOOL_NAMES)


def test_config_forwards_scope_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SCOPE_CONFIG", "engagement-scope.yaml")
    monkeypatch.setenv("STRIX_ALLOW_INTRUSIVE", "1")
    config = aws_wrapper_config(region="us-east-1")
    assert config.env["STRIX_SCOPE_CONFIG"] == "engagement-scope.yaml"
    assert config.env["STRIX_ALLOW_INTRUSIVE"] == "1"
    assert config.env["AWS_DEFAULT_REGION"] == "us-east-1"


def test_builtin_wrapper_configs() -> None:
    configs = builtin_wrapper_configs()
    assert [c.name for c in configs] == ["strix-aws"]


# --- auto-wire (applicable_builtin_configs / configs_with_builtins) -----------

def test_applicable_builtins_attaches_aws_when_in_scope() -> None:
    set_active_policy(_policy())  # has cloud.aws_account_ids
    configs = applicable_builtin_configs(set())
    assert [c.name for c in configs] == ["strix-aws"]


def test_applicable_builtins_empty_without_aws_scope() -> None:
    set_active_policy(ScopePolicy.model_validate({"web": {"domains": ["example.com"]}}))
    assert applicable_builtin_configs(set()) == []


def test_applicable_builtins_empty_without_policy() -> None:
    set_active_policy(None)
    assert applicable_builtin_configs(set()) == []


def test_applicable_builtins_skips_user_configured_name() -> None:
    set_active_policy(_policy())
    assert applicable_builtin_configs({"strix-aws"}) == []


def test_auto_wrappers_env_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX2_AUTO_WRAPPERS", "0")
    set_active_policy(_policy())
    assert applicable_builtin_configs(set()) == []


def test_configs_with_builtins_appends_and_user_wins() -> None:
    set_active_policy(_policy())
    user = [McpConnectionConfig(name="github", transport="stdio", command="x")]
    assert [c.name for c in configs_with_builtins(user)] == ["github", "strix-aws"]

    # A user's own strix-aws entry wins: no duplicate is appended.
    mine = [McpConnectionConfig(name="strix-aws", transport="stdio", command="mine")]
    merged = configs_with_builtins(mine)
    assert [c.name for c in merged] == ["strix-aws"]
    assert merged[0].command == "mine"

"""Host-side AWS read-only MCP wrapper (Strix 2, Phase 1).

Exposes a tight, **read-only** set of AWS checks over ``stdio`` MCP so the pentest
agent can produce cloud *evidence* without cloud tooling or credentials ever
entering the sandbox. Every tool:

- runs under the operator's own AWS credentials (standard boto3 resolution: env
  vars, shared config, SSO, instance role) held **on the host**, never shipped
  into the container;
- is gated by ``scope.yaml``, fail-closed: the acting principal's account (from
  STS ``GetCallerIdentity``) must be listed in ``cloud.aws_account_ids``, and with
  no scope loaded every tool refuses;
- is **non-intrusive** — no create / update / delete. State-changing proofs are
  deliberately out of scope for this wrapper.

The wrapper returns structured evidence; it does not itself file candidates or
findings. Per the validator semantics (``docs/strix2/04-validator-semantics.md``
§4.3): a "looks public" signal from ``s3_get_bucket_public_status`` is a
**candidate** the agent files with ``create_candidate``; a captured bounded read
from ``s3_get_object_head`` (request + response head + hash) is the evidence that
promotes it to a **validated** finding via ``create_vulnerability_report``.

Run as a subprocess: ``python -m strix.mcp_servers.aws`` (see
:mod:`strix.mcp_servers.registry` for the connection config Strix uses).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from strix.mcp_servers.base import ScopeGuard, build_server, error, ok


if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


logger = logging.getLogger(__name__)

# Decision 4.3b: a cloud read PoC captures only metadata + a bounded head, never
# full object contents. Object reads are clamped to this many bytes.
_MAX_HEAD_BYTES = 1024

# The read-only tool names this wrapper exposes; also its allowlist in the
# connection config, so the allowlist and the implementation cannot drift.
TOOL_NAMES = (
    "aws_whoami",
    "s3_list_buckets",
    "s3_get_bucket_public_status",
    "s3_get_object_head",
    "iam_list_principals",
    "iam_analyze_principal",
)

_INSTRUCTIONS = (
    "Read-only AWS checks for authorized cloud pentesting. Credentials stay on the "
    "host; every call is scope-gated on the caller's AWS account id. S3: "
    "s3_get_bucket_public_status files a candidate, s3_get_object_head captures the "
    "bounded read that validates it. IAM: iam_list_principals for recon, "
    "iam_analyze_principal flags over-permissive (wildcard/admin) policies as a "
    "candidate. No state-changing actions."
)

# Seam so tests inject a fake boto3 client without real AWS. Signature:
# factory(service_name, region_or_none) -> client.
_client_factory: Any = None

# Cached (account, arn) for the acting principal, resolved once via STS.
_identity: tuple[str, str] | None = None

_guard_instance: ScopeGuard | None = None


def set_client_factory(factory: Any) -> None:
    """Test seam: install a callable ``factory(service, region)`` returning a client."""
    global _client_factory  # noqa: PLW0603
    _client_factory = factory


def reset_state() -> None:
    """Test seam: clear the cached identity and guard so a test starts clean."""
    global _identity, _guard_instance  # noqa: PLW0603
    _identity = None
    _guard_instance = None


def _client(service: str, region: str | None = None) -> Any:
    if _client_factory is not None:
        return _client_factory(service, region)
    import boto3

    return boto3.client(service, region_name=region)


def _guard() -> ScopeGuard:
    global _guard_instance  # noqa: PLW0603
    if _guard_instance is None:
        _guard_instance = ScopeGuard.load()
    return _guard_instance


def _get_identity() -> tuple[str, str]:
    """Resolve and cache the acting principal's ``(account, arn)`` via STS."""
    global _identity  # noqa: PLW0603
    if _identity is None:
        ident = _client("sts").get_caller_identity()
        _identity = (str(ident.get("Account") or ""), str(ident.get("Arn") or ""))
    return _identity


def _authorize() -> tuple[str, str, None] | tuple[None, None, str]:
    """Resolve the caller and check its account is in scope (fail-closed).

    Returns ``(account, arn, None)`` when authorized, or ``(None, None, error)``
    where ``error`` is a ready-to-return tool result.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        account, arn = _get_identity()
    except (BotoCoreError, ClientError) as exc:
        return None, None, error(f"could not resolve AWS caller identity: {exc}")
    if not account:
        return None, None, error("AWS returned no account id for the caller identity")
    denial = _guard().check(f"aws:{account}", domain="cloud")
    if denial is not None:
        return None, None, denial
    return account, arn, None


def aws_whoami() -> str:
    """Return the acting AWS principal (account, ARN, user id) via STS GetCallerIdentity.

    Read-only. This is the principal every finding must name (validator semantics
    §4.3a). Refused if the caller's account is not authorized in scope.
    """
    account, arn, denial = _authorize()
    if denial is not None:
        return denial
    return ok(account=account, arn=arn)


def s3_list_buckets() -> str:
    """List S3 bucket names owned by the acting account. Read-only recon.

    Each bucket is a lead to triage, not a finding. Refused if the caller's account
    is not in scope.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    try:
        response = _client("s3").list_buckets()
    except (BotoCoreError, ClientError) as exc:
        return error(f"s3 list_buckets failed: {exc}")
    buckets = [str(b.get("Name") or "") for b in response.get("Buckets", [])]
    return ok(account=account, bucket_count=len(buckets), buckets=buckets)


def _acl_public_grants(grants: list[dict[str, Any]]) -> list[str]:
    """Return the permissions granted to 'all users' / 'authenticated users' groups."""
    public_uris = (
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    )
    public: list[str] = []
    for grant in grants:
        grantee = grant.get("Grantee") or {}
        if grantee.get("Type") == "Group" and grantee.get("URI") in public_uris:
            public.append(f"{grantee.get('URI', '').rsplit('/', 1)[-1]}:{grant.get('Permission')}")
    return public


def s3_get_bucket_public_status(bucket: str, region: str | None = None) -> str:
    """Read a bucket's public-exposure signals (ACL, policy status, public-access block).

    Read-only. Composes a ``looks_public`` signal from the bucket ACL grants, the
    bucket policy status, and the public-access-block config. A true result is a
    *candidate* (file it with create_candidate) — it is not yet a validated finding;
    prove impact with s3_get_object_head on an actual object. Refused if the
    caller's account is not in scope.

    Args:
        bucket: The S3 bucket name.
        region: Optional bucket region (e.g. ``us-east-1``).
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    if not (bucket or "").strip():
        return error("bucket is required")

    client = _client("s3", region)
    signals: dict[str, Any] = {}

    try:
        pab = client.get_public_access_block(Bucket=bucket)
        signals["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
    except (BotoCoreError, ClientError) as exc:
        signals["public_access_block"] = f"unavailable: {exc}"

    acl_public: list[str] = []
    try:
        acl = client.get_bucket_acl(Bucket=bucket)
        acl_public = _acl_public_grants(acl.get("Grants", []))
        signals["acl_public_grants"] = acl_public
    except (BotoCoreError, ClientError) as exc:
        signals["acl_public_grants"] = f"unavailable: {exc}"

    policy_is_public = False
    try:
        status = client.get_bucket_policy_status(Bucket=bucket)
        policy_is_public = bool(status.get("PolicyStatus", {}).get("IsPublic", False))
        signals["policy_is_public"] = policy_is_public
    except (BotoCoreError, ClientError) as exc:
        signals["policy_is_public"] = f"unavailable: {exc}"

    looks_public = bool(acl_public) or policy_is_public
    return ok(
        account=account,
        bucket=bucket,
        looks_public=looks_public,
        signals=signals,
        note=(
            "Candidate signal only. Prove impact with s3_get_object_head on a "
            "specific object before treating this as a finding."
        ),
    )


def s3_get_object_head(
    bucket: str,
    key: str,
    region: str | None = None,
    max_bytes: int = _MAX_HEAD_BYTES,
) -> str:
    """Read a bounded head of an S3 object as validation evidence. Read-only (GET).

    Captures the request, the response metadata, and up to ``max_bytes`` (hard-capped
    at 1024 per validator semantics §4.3b) of the object body plus its SHA-256 — the
    evidence that a should-be-private object is actually readable by the acting
    principal. Never returns full object contents. Refused if the caller's account is
    not in scope.

    Args:
        bucket: The S3 bucket name.
        key: The object key to read.
        region: Optional bucket region (e.g. ``us-east-1``).
        max_bytes: Bytes of the object head to capture (1..1024).
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, arn, denial = _authorize()
    if denial is not None:
        return denial
    if not (bucket or "").strip() or not (key or "").strip():
        return error("bucket and key are required")

    capped = max(1, min(int(max_bytes), _MAX_HEAD_BYTES))
    byte_range = f"bytes=0-{capped - 1}"
    try:
        response = _client("s3", region).get_object(Bucket=bucket, Key=key, Range=byte_range)
        body = response["Body"].read(capped)
    except (BotoCoreError, ClientError) as exc:
        return error(f"s3 get_object failed: {exc}", bucket=bucket, key=key)

    head = bytes(body)[:capped]
    return ok(
        account=account,
        principal_arn=arn,
        bucket=bucket,
        key=key,
        request={"method": "GET", "operation": "s3:GetObject", "range": byte_range},
        response_metadata={
            "content_type": response.get("ContentType"),
            "content_length": response.get("ContentLength"),
            "content_range": response.get("ContentRange"),
            "etag": response.get("ETag"),
            "last_modified": response.get("LastModified"),
        },
        bytes_captured=len(head),
        sha256=hashlib.sha256(head).hexdigest(),
        body_head_base64=base64.b64encode(head).decode("ascii"),
        note="Bounded read evidence (<=1024 bytes). Read-only proof of access.",
    )


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _coerce_policy_document(document: Any) -> dict[str, Any]:
    """Return an IAM policy document as a dict.

    IAM returns policy documents inconsistently — a dict, or a URL-encoded JSON
    string (``get_policy_version`` in particular) — so normalize both here.
    """
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        from urllib.parse import unquote

        try:
            parsed = json.loads(unquote(document))
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _concerning_statements(document: dict[str, Any], source: str) -> list[dict[str, Any]]:
    """Flag over-permissive ``Allow`` statements in one policy document.

    Concerning = an ``Allow`` with a full action wildcard (``"*"``), or a service
    wildcard (``"s3:*"``) on all resources. ``admin`` marks the classic ``*``/``*``.
    """
    flagged: list[dict[str, Any]] = []
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in _as_list(statement.get("Action"))]
        resources = [str(r) for r in _as_list(statement.get("Resource"))]
        action_star = "*" in actions
        service_wildcard = any(a.endswith(":*") for a in actions)
        resource_star = "*" in resources
        if action_star or (service_wildcard and resource_star):
            flagged.append(
                {
                    "source": source,
                    "actions": actions,
                    "resources": resources,
                    "admin": action_star and resource_star,
                    "action_wildcard": action_star,
                    "resource_wildcard": resource_star,
                }
            )
    return flagged


def iam_list_principals() -> str:
    """List IAM users and roles in the acting account. Read-only recon.

    Each principal is a lead to triage with iam_analyze_principal, not a finding.
    Refused if the caller's account is not in scope.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    iam = _client("iam")
    try:
        users = [
            {"name": str(u.get("UserName") or ""), "arn": str(u.get("Arn") or "")}
            for u in iam.list_users().get("Users", [])
        ]
        roles = [
            {"name": str(r.get("RoleName") or ""), "arn": str(r.get("Arn") or "")}
            for r in iam.list_roles().get("Roles", [])
        ]
    except (BotoCoreError, ClientError) as exc:
        return error(f"iam list principals failed: {exc}", account=account)
    return ok(account=account, user_count=len(users), users=users, roles=roles)


def iam_analyze_principal(name: str, principal_type: str) -> str:
    """Analyze an IAM user/role's policies for over-permissive (wildcard/admin) grants.

    Read-only. Reads the principal's attached managed policies and inline policies,
    then flags ``Allow`` statements with a full action wildcard or a service wildcard
    on all resources. A true ``overly_permissive`` is a **candidate** (file it with
    create_candidate) — validate it by demonstrating a should-be-denied action as the
    least-privilege principal before filing a finding. Refused if the caller's account
    is not in scope.

    Args:
        name: The IAM user name or role name (without path).
        principal_type: ``user`` or ``role``.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    account, _arn, denial = _authorize()
    if denial is not None:
        return denial
    ptype = (principal_type or "").strip().lower()
    if ptype not in ("user", "role"):
        return error("principal_type must be 'user' or 'role'")
    if not (name or "").strip():
        return error("name is required")

    iam = _client("iam")
    concerning: list[dict[str, Any]] = []
    examined: list[str] = []
    errors: list[str] = []

    try:
        if ptype == "user":
            attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
            inline_names = iam.list_user_policies(UserName=name).get("PolicyNames", [])
        else:
            attached = iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])
            inline_names = iam.list_role_policies(RoleName=name).get("PolicyNames", [])
    except (BotoCoreError, ClientError) as exc:
        return error(f"iam list policies failed for {ptype} {name!r}: {exc}", account=account)

    for policy in attached:
        arn = str(policy.get("PolicyArn") or "")
        pname = str(policy.get("PolicyName") or arn)
        try:
            default_version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            document = iam.get_policy_version(PolicyArn=arn, VersionId=default_version)[
                "PolicyVersion"
            ]["Document"]
        except (BotoCoreError, ClientError, KeyError) as exc:
            errors.append(f"managed:{pname}: {exc}")
            continue
        examined.append(f"managed:{pname}")
        concerning.extend(
            _concerning_statements(_coerce_policy_document(document), f"managed:{pname}")
        )

    for inline_name in inline_names:
        try:
            if ptype == "user":
                document = iam.get_user_policy(UserName=name, PolicyName=inline_name)[
                    "PolicyDocument"
                ]
            else:
                document = iam.get_role_policy(RoleName=name, PolicyName=inline_name)[
                    "PolicyDocument"
                ]
        except (BotoCoreError, ClientError, KeyError) as exc:
            errors.append(f"inline:{inline_name}: {exc}")
            continue
        examined.append(f"inline:{inline_name}")
        concerning.extend(
            _concerning_statements(_coerce_policy_document(document), f"inline:{inline_name}")
        )

    return ok(
        account=account,
        principal={"type": ptype, "name": name},
        overly_permissive=bool(concerning),
        concerning_statements=concerning,
        policies_examined=examined,
        errors=errors,
        note=(
            "Candidate signal only (over-permissive IAM). Validate by demonstrating an "
            "action the policy should not allow, as the least-privilege principal, "
            "before filing a finding."
        ),
    )


def build() -> FastMCP:
    """Build the AWS wrapper server with its read-only tools registered."""
    server = build_server("strix-aws", _INSTRUCTIONS)
    server.tool()(aws_whoami)
    server.tool()(s3_list_buckets)
    server.tool()(s3_get_bucket_public_status)
    server.tool()(s3_get_object_head)
    server.tool()(iam_list_principals)
    server.tool()(iam_analyze_principal)
    return server


def main() -> None:
    """Entry point: load scope in this subprocess and serve over stdio."""
    _guard()  # load scope policy now so a misconfig surfaces at startup, on stderr
    build().run()


if __name__ == "__main__":
    main()

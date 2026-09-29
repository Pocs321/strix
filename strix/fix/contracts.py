"""Versioned contracts for verified fix preparation."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


if TYPE_CHECKING:
    from collections.abc import Mapping


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceIdentityKind(StrEnum):
    COMMIT = "commit"
    ARCHIVE = "archive"


class PreparationState(StrEnum):
    PREPARING = "preparing"
    READY = "ready"
    BLOCKED = "blocked"
    FAILED = "failed"
    STALE = "stale"


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class VerificationTarget(StrEnum):
    BASE = "base"
    PATCHED = "patched"


class VerificationDecision(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class RepairStatus(StrEnum):
    COMPLETE = "complete"
    BLOCKED = "blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INCOMPLETE = "incomplete"


class BlockerKind(StrEnum):
    SOURCE = "source"
    ENVIRONMENT = "environment"
    REPOSITORY_BASELINE = "repository_baseline"
    CREDENTIAL = "credential"
    EXTERNAL_CONFIGURATION = "external_configuration"
    SECURITY_EVIDENCE = "security_evidence"
    VERIFICATION_RUNTIME = "verification_runtime"


class PreparationBlocker(ContractModel):
    kind: BlockerKind
    summary: str = Field(min_length=1)
    user_action: str = Field(min_length=1)
    details: list[str] = []


class SourceIdentity(ContractModel):
    kind: SourceIdentityKind
    value: str = Field(min_length=1)
    repository: str | None = None

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized or any(char not in "0123456789abcdef" for char in normalized):
            raise ValueError("source identity must be a hexadecimal digest")
        return normalized

    @model_validator(mode="after")
    def validate_digest_length(self) -> SourceIdentity:
        valid_lengths = {40, 64} if self.kind is SourceIdentityKind.COMMIT else {64}
        if len(self.value) not in valid_lengths:
            expected = "40 or 64" if self.kind is SourceIdentityKind.COMMIT else "64"
            raise ValueError(f"{self.kind} identity must contain {expected} hexadecimal characters")
        return self


def _validate_relative_path(value: str) -> str:
    path = value.strip()
    parsed = PurePosixPath(path)
    if not path or parsed.is_absolute() or ".." in parsed.parts or path.startswith("./"):
        raise ValueError("path must be relative to the repository root")
    return path


class CandidateLocation(ContractModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str | None = None
    label: str | None = None

    _relative_file = field_validator("file")(_validate_relative_path)

    @model_validator(mode="after")
    def validate_range(self) -> CandidateLocation:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class FixEdit(CandidateLocation):
    before: str = Field(min_length=1)
    after: str
    original_sha256: str | None = None


class CommandSpec(ContractModel):
    name: str = Field(min_length=1, max_length=120)
    argv: list[str] = Field(min_length=1)
    required: bool = True
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    cwd: str = "."

    _relative_cwd = field_validator("cwd")(_validate_relative_path)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any(not argument or "\x00" in argument for argument in value):
            raise ValueError("command arguments must be non-empty and cannot contain NUL")
        return value


class ReproductionSpec(ContractModel):
    instructions: str = Field(min_length=1)
    command: CommandSpec | None = None


class ReportedCheck(ContractModel):
    name: str
    result: str
    executed: bool = False


class FindingContext(ContractModel):
    title: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""


class FixCandidateV1(ContractModel):
    version: Literal["1"] = "1"
    source_identity: SourceIdentity | None = None
    security_invariant: str = Field(min_length=1)
    finding_locations: list[CandidateLocation] = []
    draft_edits: list[FixEdit] = []
    reproduction: ReproductionSpec | None = None
    reported_checks: list[ReportedCheck] = []
    known_gaps: list[str] = []
    finding: FindingContext | None = None

    def digest(self) -> str:
        data = self.model_dump(mode="json")
        if self.finding is None:
            data.pop("finding", None)  # Preserve digests for stored legacy candidates.
        payload = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()


class FixPreparationRequestV1(ContractModel):
    version: Literal["1"] = "1"
    organization_id: str | None = None
    scan_id: str
    finding_id: str
    repository_id: str | None = None
    candidate: FixCandidateV1
    checks: list[CommandSpec] = []
    max_repair_attempts: int = Field(default=2, ge=1, le=2)
    timeout_seconds: int = Field(default=1800, ge=30, le=14400)
    network_allowed: bool = False
    credentials_allowed: list[str] = []


class CheckResult(ContractModel):
    name: str
    argv: list[str]
    status: CheckStatus
    exit_code: int | None = None
    duration_seconds: float = Field(ge=0)
    output: str = ""
    required: bool = True
    target: VerificationTarget | None = None
    baseline_status: CheckStatus | None = None
    baseline_output: str | None = None
    cwd: str = "."
    baseline_exit_code: int | None = None
    failure_kind: (
        Literal["environment", "timeout", "check", "source_changed", "harness", "unknown"] | None
    ) = None
    workspace_root: str | None = None
    baseline_workspace_root: str | None = None
    source_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    environment_id: str | None = None


class RegressionTestResult(ContractModel):
    """One unchanged test run on both revisions, plus a legitimate-operation check."""

    name: str
    expected_base_failure: str = Field(min_length=1)
    harness_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base: CheckResult
    patched: CheckResult
    behavior: CheckResult

    def passed(self) -> bool:
        results = (self.base, self.patched, self.behavior)
        # Legacy records remain readable. Once provenance is supplied, every leg
        # must have it and the environment must be unchanged across the pair.
        if any(item.source_digest or item.environment_id for item in results) and (
            not all(item.source_digest and item.environment_id for item in results)
            or len({item.environment_id for item in results}) != 1
            or self.patched.source_digest != self.behavior.source_digest
        ):
            return False
        return (
            self.base.target is VerificationTarget.BASE
            and self.patched.target is VerificationTarget.PATCHED
            and self.behavior.target is VerificationTarget.PATCHED
            and self.base.argv == self.patched.argv
            and self.base.cwd == self.patched.cwd
            and self.base.status is CheckStatus.FAILED
            and self.base.exit_code == 1
            and self.base.failure_kind in {None, "check"}
            and self.expected_base_failure in self.base.output
            and self.patched.status is CheckStatus.PASSED
            and self.patched.exit_code == 0
            and self.behavior.status is CheckStatus.PASSED
            and self.behavior.exit_code == 0
        )


class VerificationHarness(ContractModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content: str


class VerifierResult(ContractModel):
    decision: VerificationDecision
    summary: str
    security_invariant_closed: bool = False
    reproduction_executed: bool = False
    reproduction_summary: str | None = None
    sibling_paths_reviewed: list[str] = []
    preserved_behaviors: list[str] = []
    gaps: list[str] = []
    security_tests: list[CheckResult] = []
    repairable: bool = False
    blocker: PreparationBlocker | None = None
    regression_tests: list[RegressionTestResult] = []
    harnesses: list[VerificationHarness] = []
    notes: list[str] = []


class RepairOutcome(ContractModel):
    status: RepairStatus
    summary: str = Field(min_length=1)
    gaps: list[str] = []
    reproduction_command: CommandSpec | None = None
    turns_used: int = Field(default=0, ge=0)
    blocker: PreparationBlocker | None = None
    checks: list[CommandSpec] = []
    command_results: list[CheckResult] = []


class FixPreparationAttempt(ContractModel):
    attempt: int = Field(ge=1)
    repair: RepairOutcome
    checks: list[CheckResult] = []
    security_reproduction: CheckResult | None = None
    verifier: VerifierResult | None = None
    workspace_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class FileManifestEntry(ContractModel):
    path: str
    operation: Literal["add", "modify", "delete"]
    original_sha256: str | None = None
    resulting_sha256: str | None = None
    artifact_ref: str | None = None

    _relative_path = field_validator("path")(_validate_relative_path)


class FixPreparationResultV1(ContractModel):
    version: Literal["1"] = "1"
    state: PreparationState
    stop_reason: str
    source_identity: SourceIdentity | None
    candidate: FixCandidateV1
    candidate_digest: str
    final_file_manifest: list[FileManifestEntry] = []
    artifact_ref: str | None = None
    changed_files: list[str] = []
    diff_summary: str = ""
    checks: list[CheckResult] = []
    security_reproduction: CheckResult | None = None
    verifier: VerifierResult | None = None
    attempt_history: list[FixPreparationAttempt] = []
    gaps: list[str] = []
    blocker: PreparationBlocker | None = None
    setup_checks: list[CheckResult] = []
    attempts: int = Field(default=0, ge=0)
    elapsed_seconds: float = Field(default=0, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)


def candidate_from_legacy_report(
    report: Mapping[str, object],
    *,
    source_identity: SourceIdentity | None = None,
) -> FixCandidateV1 | None:
    raw_locations = report.get("code_locations")
    if not isinstance(raw_locations, list):
        return None
    location_values = cast("list[object]", raw_locations)

    locations: list[CandidateLocation] = []
    edits: list[FixEdit] = []
    for raw_value in location_values:
        if not isinstance(raw_value, dict):
            continue
        raw = cast("dict[str, object]", raw_value)
        file_path = raw.get("file")
        start_line = raw.get("start_line")
        end_line = raw.get("end_line")
        if not isinstance(file_path, str) or type(start_line) is not int:
            continue
        if type(end_line) is not int:
            end_line = start_line
        common = {
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "snippet": raw.get("snippet") if isinstance(raw.get("snippet"), str) else None,
            "label": raw.get("label") if isinstance(raw.get("label"), str) else None,
        }
        try:
            locations.append(CandidateLocation.model_validate(common))
            before = raw.get("fix_before")
            after = raw.get("fix_after")
            if isinstance(before, str) and isinstance(after, str):
                edits.append(FixEdit.model_validate({**common, "before": before, "after": after}))
        except ValueError:
            continue

    if not locations:
        return None

    invariant = str(
        report.get("remediation_steps") or report.get("technical_analysis") or ""
    ).strip()
    if not invariant:
        invariant = "Resolve the reported security finding without changing legitimate behavior."

    reported_checks: list[ReportedCheck] = []
    verification = str(report.get("fix_verification") or "").strip()
    if verification:
        reported_checks.append(
            ReportedCheck(name="reporting-agent verification", result=verification, executed=False)
        )

    reproduction = str(report.get("poc_description") or report.get("evidence") or "").strip()
    return FixCandidateV1(
        source_identity=source_identity,
        security_invariant=invariant,
        finding_locations=locations,
        draft_edits=edits,
        reproduction=ReproductionSpec(instructions=reproduction) if reproduction else None,
        finding=FindingContext(
            title=str(report.get("title") or ""),
            description=str(report.get("description") or report.get("technical_analysis") or ""),
            evidence=str(report.get("evidence") or report.get("poc_description") or ""),
            remediation=str(report.get("remediation_steps") or ""),
        ),
        reported_checks=reported_checks,
        known_gaps=["The reporting-agent verification is not independent."],
    )

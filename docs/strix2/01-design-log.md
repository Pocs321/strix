# Strix 2 — Design Log

A running log of decisions, tradeoffs, and **every core-file change** (with a one-line justification),
per build-brief §2 and §6. Newest entries at the bottom of each phase.

Fork base: `usestrix/strix` @ `ae38fe70` (`main`), version 1.6.2. Working branch: `strix2`.
Upstream kept as git remote `upstream` for rebasing; `origin` intentionally unset until the maintainer
decides where to push (creating a GitHub fork is an outward action — deferred to an explicit go-ahead).

## Conventions
- **Additive-first.** New capability = new module/skill/agent. Editing an upstream file requires an
  entry in the "Core-file changes" table below with a one-line reason.
- New files carry the Apache-2.0 header used by the file's neighbours.
- Every new tool/agent/validator rule ships with a test; CI stays green.

## Core-file changes (upstream files we edited)
| File | Change | Reason | Phase |
|---|---|---|---|
| `strix/core/runner.py` | +1 import, +1 call to `install_strix2_extensions(run_dir)` after `set_scan_id` in `run_strix_scan` | Single, idempotent hook to register Strix 2's additive tools/stores at run start via the built-in `register_agent_tools` seam (which had no upstream callers). 2 lines added, none changed. | 4 |
| `strix/report/writer.py` | +2 imports, `write_executive_report` appends a best-effort "Leads (unvalidated)" section via new `_strix2_leads_section()` | Surface candidate leads in the report `strix view` renders. Guarded/no-op when the candidate store is absent or empty, so upstream-only runs are unchanged. | 4 |
| `strix/tools/mcp/agent_tools.py` | +1 import, `call_mcp` calls new `_scope_denial(arguments)` before dispatch | Enforce `scope.yaml` at the MCP boundary the brief names. No-op when no policy is loaded / no high-confidence target found, so upstream MCP behavior is unchanged. | 1 |
| `strix/interface/cli_args.py` | Added `--scope-config` and `--allow-intrusive` flags → set `STRIX_SCOPE_CONFIG` / `STRIX_ALLOW_INTRUSIVE` env (mirrors the existing `--mcp-*` pattern) | Let the operator point at a scope file and gate intrusive actions from the CLI. | 1 |
| `pyproject.toml` | +`boto3.*`/`botocore.*` to the mypy `ignore_missing_imports` overrides; +a ruff per-file `PLC0415` ignore for `strix/mcp_servers/aws.py` | boto3 ships no type stubs (mypy strict), and the wrapper imports boto3/botocore lazily so the main process never drags in the heavy SDK. Config-only; no product-code change. | 1 |

> As of Phase 0, **zero upstream files edited.** All Phase 0 additions are new files
> (`docs/strix2/*`, `scope.yaml`, `strix/scope/*`, `.github/workflows/ci.yml`, `THIRD_PARTY.md`,
> `tests/test_strix2_scope.py`). New tests use a flat `tests/test_strix2_*.py` naming (matches
> upstream's flat layout and avoids ruff `INP001`) rather than a `tests/strix2/` subdir.

---

## Phase 0 — Bootstrap

**Environment (2026-09-26, Windows 11 / PowerShell + Git Bash).**
- Tooling present: git 2.53, uv 0.11.7, Python 3.13.9, docker CLI 29.4.1, node 24. `nmap` **not** on host
  (expected — network tools live in the sandbox image, not on the host).
- `uv sync --dev` → OK. `uv run strix --version` → `strix 1.6.2`.
- **Test baseline (Windows host):** `2171 passed, 32 failed, 11 skipped, 3 xfailed` in ~9m. **All 32
  failures are POSIX-only test-harness assumptions, not product bugs**, verified by cause:
  `test_viewer_auth`/`test_config_loader` assert `0o600` file modes (`assert 438 == 384`, i.e. Windows'
  `0o666`); `test_threat_model_tool` (×21) hardcode `/usr/bin/env git` (`WinError 2`);
  `test_session_entries` uses symlinks; `test_completions` uses filenames with terminal-control chars
  Windows forbids; `test_workspace_files`/`test_local_sources` are path-separator sensitive. **Every seam
  Strix 2 builds on passes** (`test_cli_mcp_config`, `test_agent_tool_registration`, `test_dedupe_model`,
  `test_e2e_budget_lifecycle`, `test_agent_graph_coordination`). CI runs on Linux, where these pass; the
  local Windows baseline is "green modulo known POSIX-only cases."
- **Blocker for a live baseline scan:** the **Docker daemon is not running** (Docker Desktop Linux engine
  npipe not found), and a real scan additionally needs an LLM API key + spends budget. Deferred — see
  "Open decisions".

**Decision — git topology.** Cloned upstream into the working dir, renamed `origin`→`upstream`, created
branch `strix2`. Keeps history rebaseable; no GitHub fork created yet (outward/irreversible — needs
explicit go-ahead).

**Decision — where new code lives.** Confirmed the two clean seams from the codebase map:
`register_agent_tools()` (native tools) and `register_skill_dir()` (skills) let us extend without touching
`agents/factory.py` or the skill loader. Scope enforcement gets its own new package `strix/scope/`.

**Decision — `scope.yaml` schema (drafted + loaded, enforcement stubbed).** Added `strix/scope/` with a
pydantic v2 schema (`ScopePolicy`) and a fail-closed loader, plus a root-level `scope.yaml` template. The
schema models authorized **web** origins, **network** IPs/CIDRs/hostnames+ports, **cloud** account IDs
(AWS/Azure/GCP) and regions, **API** base URLs, and an `allow_intrusive` default (off). Enforcement
(`is_in_scope(target)` returning allow/deny + reason) is implemented as a pure function now; wiring it into
the MCP wrapper boundary and native tools is Phase 1. Rationale for doing the schema in Phase 0: the brief
makes scope a *precondition* for the scope-expansion phases, and a stubbed-but-real schema lets later
phases import a stable contract instead of inventing one ad hoc. See `docs/strix2/scope-schema.md`.

**Decision — CI.** Upstream ships only a tag-triggered release workflow, so `ci.yml` is net-new: it runs
`uv sync --dev`, `ruff check`, and `pytest` on push/PR (Linux, Python 3.12 + 3.13). Kept minimal and
non-duplicative of the release workflow.

**Correction to the brief (recorded for later phases).** Several mechanisms the brief lists as
missing already exist upstream and must not be rebuilt: `--max-budget-usd`, `--max-turns`,
per-turn loop/tool-call guard (`_TurnGuardModel`), LLM finding-dedup, and cloud/network *methodology*
skills. Phase 5 is therefore re-scoped to *model router + cross-run caching + no-progress detector*.
Full detail in `00-codebase-map.md` §7–§10.

### Open decisions / need maintainer input
- **Phase 4 PoC semantics (the crux).** ✅ **Signed off 2026-09-26** — all 8 decisions adopted at their
  recommended defaults (see `04-validator-semantics.md`). Candidate tier implemented (see Phase 4 below).
- **Live baseline scan.** Needs (a) Docker daemon started, (b) an LLM API key, (c) authorization to spend
  budget against a local vulnerable app. Maintainer confirmed **OpenRouter** as the intended provider —
  supported natively via LiteLLM (`openrouter/<model>` + `LLM_API_KEY`); still awaiting the key + a
  `--max-budget-usd` ceiling before running (won't spend unprompted).
- **GitHub fork / push target.** Where should `origin` point? (Still unset; CI unverified on a real Linux
  runner until a push happens.)

### Phase 0 acceptance status
- [x] Codebase map complete → `00-codebase-map.md`
- [x] Design log started → this file
- [x] `scope.yaml` schema drafted **and loaded** (enforcement stubbed) → `strix/scope/`, `scope.yaml`
- [x] CI runs upstream + new tests → `.github/workflows/ci.yml` (+ `tests/test_strix2_scope.py`)
- [ ] Baseline scan produces a validated web finding with a PoC → **blocked** (Docker daemon + API key + budget go-ahead)

---

## Phase 1 — Scope enforcement (core landed; MCP wrappers pending)

Enforcement engine + boundary wiring + CLI gate, all tested. **What's left of Phase 1: the actual MCP
wrapper servers** (nmap/naabu/masscan; prowler/ScoutSuite/CloudFox; nuclei/trivy/checkov; API contract)
with tight `allowed_tools` — a separate, larger chunk not yet started.

**Built:**
- `strix/scope/enforcement.py` — active-policy holder (`get/set_active_policy`), `load_active_policy`
  (reads `scope.yaml`/`$STRIX_SCOPE_CONFIG`, applies `--allow-intrusive`/`STRIX_ALLOW_INTRUSIVE`),
  conservative `extract_targets` (URLs/ARNs/IPv4/12-digit only — bare hostnames excluded to avoid
  false-positives), `enforce_target`, `enforce_arguments`.
- `strix/tools/scope/tools.py` — `check_scope(target, intrusive)` and `scope_status` agent tools.
- Wired into `call_mcp` (guarded, no-op without a policy) and loaded at run start in `strix2_ext`.
- `--scope-config` / `--allow-intrusive` CLI flags.
- Tests: `tests/test_strix2_scope_enforcement.py` (extraction, checks, intrusive gate, loading/overrides).

**Compatibility stance (documented):** enforcement is active only when a `scope.yaml` is loaded; absent,
upstream web/MCP behavior is unchanged. The "fail-closed without scope" requirement applies to the new
intrusive domains (network/cloud), enforced inside those tools when they land in Phase 3.

### Phase 1 (cont.) — host-side MCP wrapper framework + first cloud wrapper

**Architecture decision (brief vs. codebase-map — the map wins).** The brief lists Phase 1 as "stdio MCP
servers wrapping nmap/naabu/masscan (network), prowler/… (cloud), nuclei/trivy/checkov (infra)". Verified
against the code, an MCP `stdio` server is a **host-side subprocess** (`client._build_server` →
`MCPServerStdio` → `stdio_client` spawns `command` on the host, in Strix's own venv). So:
- **Cloud → host-side MCP wrapper.** Cloud tooling is genuinely absent from the sandbox and cloud creds
  must stay *off* the sandbox (codebase-map §8). A host-side subprocess is exactly right: it holds creds on
  the host and reuses `strix.scope` in-process. **This is where the MCP-wrapper mechanism pays off.**
- **Network/infra → NOT host-side MCP.** Those CLIs already live *in the sandbox* and are reached via
  `exec_command`; a host-side subprocess cannot see them. Wrapping them host-side would run against a host
  that doesn't have the tools. They instead get the scope + candidate discipline as **in-sandbox native
  tools / skills** (Phase 2/3), layered on the already-present CLIs — not as MCP wrappers.
- **API contract testing** is pure-Python and host-runnable; a candidate for a later host-side wrapper or a
  native tool. Deferred.

**Built (framework):** `strix/mcp_servers/base.py` — `ScopeGuard` (loads the policy *in the subprocess*
and gates targets **fail-closed for the new domains**: no `scope.yaml` ⇒ refuse, unlike the web/MCP
boundary), `ok`/`error`/`result` JSON-string helpers (a `stdio` server must never `print` — stdout is the
protocol), and `build_server` (a `FastMCP` stdio server). `mcp.server.fastmcp` and `boto3` are both already
present (the latter transitively via `litellm`). Tests: `tests/test_strix2_mcp_wrapper_base.py` (8).

**Built (AWS read-only wrapper):** `strix/mcp_servers/aws.py` — `aws_whoami` (STS identity → names the
principal per validator decision 4.3a), `s3_list_buckets`, `s3_get_bucket_public_status` (composes a
`looks_public` **candidate** signal from ACL/policy-status/public-access-block, read-only), and
`s3_get_object_head` (a bounded **≤1 KiB** object read capturing request + response head + SHA-256 — the
**validation evidence** per decisions 4.3b/5a). Every tool resolves the caller account via STS and refuses
unless it is in `cloud.aws_account_ids`; all tools are read-only (no state change). A client-factory seam
injects a fake boto3 in tests, so the suite needs no AWS creds or network. Tests:
`tests/test_strix2_mcp_aws.py` (15). This exercises the acceptance walk-through (§8 of the validator doc):
public-bucket signal → candidate; bounded read → validated evidence.

**Registration model.** `strix/mcp_servers/registry.py::aws_wrapper_config()` emits the
`McpConnectionConfig` (a `stdio` entry: `<python> -m strix.mcp_servers.aws`, tight `allowed_tools`,
forwards `STRIX_SCOPE_CONFIG`/`STRIX_ALLOW_INTRUSIVE` to the subprocess). For now an operator registers it
in `~/.strix/mcp-servers.json` (or `--mcp-config`); `builtin_wrapper_configs()` is the list a future
auto-wire hook would attach at run start. CI blocking gate extended to lint+typecheck `strix/mcp_servers`.

**Known verification gap.** The wrapper's *live* behavior (real subprocess spawn + MCP connect + real AWS)
is not covered by an automated test — it needs AWS creds and a lab account. Unit tests cover scope gating,
argument handling, evidence shaping, tool registration, and the config. A live integration test is
deferred to an environment with credentials (or the managed cloud). Also to verify there: that the `mcp`
`stdio` transport forwards the passthrough env and inherits CWD as assumed.

### Baseline scan via 9Router (dogfooding) — Phase 0 pipeline verified + first self-found fix

**2026-09-30.** Ran the first real end-to-end scan now that Docker is up, using the operator's local
**9Router** (an OpenAI-compatible gateway) as the LLM instead of a paid OpenRouter key — verified
connectable and wired (see the `strix-llm-via-9router` note for the config: `STRIX_LLM=openai/<id>` **must**
keep the `openai/` prefix, `LLM_API_BASE=http://localhost:20128/v1`). Command:
`uv run strix -n -t ./ --scan-mode quick --max-turns 25` with `openai/cc/claude-sonnet-5`.

- **Pipeline works end-to-end through 9Router:** `status: completed`, 22 LLM requests with tool-calls, the
  sandbox built and the report/SARIF/`run.json` artifacts were written (`strix_runs/strix2_4ef2/`).
- **0 validated findings** — correct: no PoC was built (the run hit the 25-turn budget first), so nothing
  was filed. The no-false-positive discipline held.
- **The scan found a real bug in our own Phase 0 scope code** and, correctly, recorded it as a
  `needs_follow_up` lead rather than a finding: `strix/scope/schema.py::_url_prefix_matches` used a plain
  `startswith`, so an authorized `api.base_urls` entry `.../v1` also matched `.../v1extra` (same-host
  path-scope widening; also a look-alike-host prefix match when a base has no path). **Fixed**: the match
  now requires a `/`, `?`, `#`, or end-of-string boundary after the base. Regression tests added
  (`test_api_base_url_requires_path_boundary`, `test_api_base_url_without_path_rejects_lookalike_host`).
- **Cost/perf note:** $5.27 for 22 turns (2.5M input tokens). 9Router returned **no prompt-cache hits**
  (`cached_tokens: 0`), so each turn re-billed the full ~100–140 K context — expensive per turn. Keep
  `--max-turns` low over 9Router, prefer a cheaper model (`ds/*`) for routine runs, and note Strix's
  `--max-budget-usd` did track cost here but cannot be relied on for arbitrary gateway model ids.

Phase 0 acceptance ("a **validated** web finding with a PoC") still needs a **running vulnerable web app**
as target; `-t ./` is a code review and proved the pipeline, not that gate.

## Phase 4 — Generalized finding + PoC validator (in progress)

Semantics signed off (`04-validator-semantics.md`, all defaults). Landed the **candidate (lead) tier** —
the low-bar half of the two-tier model — as an additive package plus one 2-line hook in `core/runner.py`.

**Built:**
- `strix/candidates/` — `Candidate` schema (pydantic, `extra=forbid`, `dedup_key`, status lifecycle) and
  `CandidateStore` (in-run store, `cand-NNNN` ids, structural dedup against open candidates *and* validated
  findings per decision 3a, persists `candidates.json` beside `vulnerabilities.json`, promote/dismiss).
- `strix/tools/candidates/tools.py` — `create_candidate`, `list_candidates`, `promote_candidate`,
  `dismiss_candidate` (`@function_tool`s). Deliberately omits `from __future__ import annotations` so the
  SDK resolves the `RunContextWrapper` context annotation at registration without a ruff `TC002` ignore.
- `strix/strix2_ext.py::install_strix2_extensions(run_dir)` — idempotent bootstrap that registers the
  candidate tools via the (previously caller-less) `register_agent_tools` seam and binds the store to the
  run dir. Wired in at the top of `run_strix_scan` (the single core edit).
- `tests/test_strix2_candidates.py` — 13 tests (schema, dedup incl. cross-tier, lifecycle, persistence,
  registration/idempotency). All green; ruff + mypy clean. CI blocking gate extended to lint+typecheck the
  new code.

**Design choices:** candidates are a *separate* store (no edit to `ReportState`) so they stay rebaseable;
they never enter the finding count; dedup is structural now (deterministic/testable), with semantic LLM
dedup as a follow-up. Attribution (`agent_id`/`agent_name`) is captured on each candidate.

**Leads rendering (decision 3b) — done.** `strix/candidates/writer.py` renders `LEADS.md` (written by the
store on every persist) and the "Leads (unvalidated)" section appended to `penetration_test_report.md`
(one guarded, logged `write_executive_report` edit — no-op for upstream-only runs). 5 more tests; report
writer + import-warmup suites stay green (119 passed).

**Not yet (next Phase 3/4 steps):** network/cloud *validated* finding classes + their evidence channels
(captured request/response, cloud principal + denying policy, runtime repro); scope-coupled proof (needs
Phase 1 enforcement); MITRE ATT&CK/CIS optional fields on the validated schema.

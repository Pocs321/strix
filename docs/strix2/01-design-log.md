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
| _(none yet)_ | | | |

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
- **Phase 4 PoC semantics (the crux).** Before coding validators, confirm the exact "demonstrated impact"
  bar per domain (network / cloud / infra) and the candidate→validated promotion rule. The brief gives a
  strong starting definition; per brief §5 we will not silently pick one. Draft proposal will land in
  `docs/strix2/04-validator-semantics.md` for sign-off.
- **Live baseline scan.** Needs (a) Docker daemon started, (b) an LLM API key, (c) authorization to spend
  budget against a local vulnerable app. Awaiting go-ahead before spending.
- **GitHub fork / push target.** Where should `origin` point?

### Phase 0 acceptance status
- [x] Codebase map complete → `00-codebase-map.md`
- [x] Design log started → this file
- [x] `scope.yaml` schema drafted **and loaded** (enforcement stubbed) → `strix/scope/`, `scope.yaml`
- [x] CI runs upstream + new tests → `.github/workflows/ci.yml` (+ `tests/test_strix2_scope.py`)
- [ ] Baseline scan produces a validated web finding with a PoC → **blocked** (Docker daemon + API key + budget go-ahead)

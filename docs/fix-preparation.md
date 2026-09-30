# Fixing findings during a scan

- The assessment investigates and validates an issue, then saves its vulnerability report.
- Saving a confirmed, source-backed report automatically starts a Fix agent through the standard child spawner. No model handoff is required. Duplicate notifications reuse the current job; changed candidates invalidate it and start a replacement. Unconfirmed findings and explicit blockers are not eligible.
- Each finding gets a Git worktree in the scan's existing sandbox. Fixes run concurrently; the original checkout remains available for assessment and attack chaining.
- One native Strix child implements the complete fix, retains a regression test, runs it and relevant existing customer unit tests, and runs applicable build/lint/type checks. Before finishing it checks alternate paths to the same attack and affected legitimate callers. Broader suites need a reason; dismissing a relevant failure as pre-existing needs a comparison with the unchanged revision. Test selection and recovery belong to the agent.
- The agent calls `agent_finish(success=True)` or `agent_finish(success=False)`. The controller enforces **300 total model turns per finding**, including resumed execution and candidate revisions. It does not start a fresh agent after exhaustion.
- The finish tool checkpoints source before completing. Packaging errors return to the agent for correction; three identical completion errors stop the job with that reason. Untracked dependency/cache paths stay out of the patch; new source and tests stay in. Only a completed, nonempty patch becomes an artifact. Blocked, interrupted, or capped work produces no deliverable patch.
- Assessment completion publishes the security report. Fixes may continue in the same sandbox; execution and sandbox cleanup finish after all Fix tasks stop. Scan cancellation and the shared model budget also stop fix work.
- In the hosted app, successful fixes become available for **user-initiated draft PR creation** on the issue. Incomplete patches are not shown. Internal diagnostic logs and terminal status remain available to operators.

## Implementation

- `strix/tools/reporting/tool.py`: persists the finding and its confirmed/unconfirmed validation status.
- `strix/report/state.py`: notifies the fix launcher only after persistence succeeds.
- `strix/core/execution.py`: registers, runs, and completes Fix children through the normal child lifecycle.
- `strix/fix/scan.py`: supplies the finding/worktree, deduplicates requests, preserves turn counts, exports completion, and cleans up. It replays persisted findings on resume. Terminal failures are reported truthfully; an explicit retry starts a fresh attempt using the remaining turn allowance.
- `strix/runtime/agent_session.py`: borrows the scan sandbox with a worktree-specific filesystem root and process ownership. All scan agents get a process scope. Use `stop_process` or Ctrl-C on an owned tool session; broad shell kill commands are rejected. This prevents accidental interference, not hostile code escaping an OS security boundary.
- `strix/agents/prompts/fix.jinja`: the single Fix assignment; shared workspace guidance is in `fix_workspace.jinja`.
- `strix/fix/runtime.py`: uses `build_strix_agent`, `run_agent_loop`, native tools, persisted sessions, and usage hooks. There is no separate reviewer or custom conversation loop.
- `strix/fix/prepare.py`: checks source identity and the completed patch, then exports successful artifacts.
- Pro supplies progress/result callbacks. The app registers the inline attempt, stores successful artifacts privately, and creates draft PRs using its existing repository integration. Neither starts another fix sandbox.

The `single_agent` result contract exposes the agent's limitations in both `completion.gaps` and top-level `gaps` for compatible readers. It records the Fix agent's completion, command history, final file manifest, and source digest. It does not claim independent verification. Commands include diagnostic failures and superseded attempts; the agent's final summary explains which tests passed and any optional follow-ups.

## Standalone OSS command

`strix fix --finding findings.json --finding-id FINDING_ID --repo /path/to/repo`

The standalone command uses the same single-agent implementation in its own sandbox, because no live scan exists to borrow. It preserves the supplied checkout and writes private outputs outside the repository by default. Only successful runs export a patch and archive. `--max-agent-turns` and the legacy `--max-repair-turns` can lower the turn cap; they cannot raise it above 300. Old request fields are accepted for compatibility, but reviewer limits no longer control a second agent.

Uploaded archives and ambiguous multiple-repository findings cannot currently start an automatic worktree fix: the candidate must identify one Git source and its exact revision.

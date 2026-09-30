# Fixing findings during a scan

- The assessment investigates and validates an issue, then saves its vulnerability report.
- A confirmed report with an actionable source-backed candidate starts a Fix agent immediately. Unconfirmed reports, duplicate reports, and explicit candidate blockers do not start one.
- Each finding gets a Git worktree in the scan's existing sandbox. Fixes run concurrently; the original checkout remains available for assessment and attack chaining.
- One native Strix agent implements the complete fix, adds a regression test, runs it and relevant existing customer unit tests, runs applicable build/lint/type checks, and reviews the change. Test selection and recovery belong to the agent.
- The agent calls `agent_finish(outcome="done")` or `agent_finish(outcome="blocked")`. The controller enforces **300 total model turns per finding**, including resumed execution and candidate revisions. It does not start a fresh agent after exhaustion.
- The controller binds completion to the final source checkpoint. Only a completed, nonempty patch becomes an artifact. Blocked, interrupted, or capped work produces no deliverable patch.
- Assessment completion publishes the security report. Fixes may continue in the same sandbox; execution and sandbox cleanup finish after all Fix tasks stop. Scan cancellation and the shared model budget also stop fix work.
- In the hosted app, successful fixes become available for **user-initiated draft PR creation** on the issue. Incomplete patches are not shown. Internal diagnostic logs and terminal status remain available to operators.

## Implementation

- `strix/tools/reporting/tool.py`: persists the finding and its confirmed/unconfirmed validation status.
- `strix/report/state.py`: notifies the scan only after successful finding persistence.
- `strix/fix/scan.py`: deduplicates tasks, creates independent worktrees, preserves turn counts, and joins/cancels tasks during scan teardown.
- `strix/fix/session.py`: borrows the scan sandbox with a worktree-specific filesystem root and process ownership. Cleanup never stops another agent's processes.
- `strix/agents/prompts/fix.jinja`: the single Fix assignment; shared workspace guidance is in `fix_workspace.jinja`.
- `strix/fix/runtime.py`: uses `build_strix_agent`, `run_agent_loop`, native tools, persisted sessions, and usage hooks. There is no separate reviewer or custom conversation loop.
- `strix/fix/prepare.py`: checks source identity and the completed patch, then exports successful artifacts.
- Pro supplies progress/result callbacks. The app registers the inline attempt, stores successful artifacts privately, and creates draft PRs using its existing repository integration. Neither starts another fix sandbox.

The `single_agent` result contract records the Fix agent's completion, command history, final file manifest, and source digest. It does not claim independent verification. Commands include diagnostic failures and superseded attempts; the agent's final summary explains which tests passed and any optional follow-ups.

## Standalone OSS command

`strix fix --finding findings.json --finding-id FINDING_ID --repo /path/to/repo`

The standalone command uses the same single-agent implementation in its own sandbox, because no live scan exists to borrow. It preserves the supplied checkout and writes private outputs outside the repository by default. Only successful runs export a patch and archive. `--max-agent-turns` and the legacy `--max-repair-turns` can lower the turn cap; they cannot raise it above 300. Old request fields are accepted for compatibility, but reviewer limits no longer control a second agent.

Uploaded archives and ambiguous multiple-repository findings cannot currently start an automatic worktree fix: the candidate must identify one Git source and its exact revision.

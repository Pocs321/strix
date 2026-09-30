# Fix preparation

The workflow is **repair → review → reviewed patch**. Both agents use Strix's existing
agent loop, native filesystem and shell tools, and saved conversations. They share
one persistent sandbox. The assignments live in `strix/agents/prompts/fix_repair.jinja` and
`fix_review.jinja`, with shared workspace instructions in `fix_workspace.jinja`.

Repair receives the finding, evidence, affected locations, suggested remediation,
and available reproduction details. It makes a minimal fix, adds a regression test
using the repository's framework, and hands the test location and commands to review.
Review receives the finding, patch, repair summary, and command history. It runs
the customer's relevant existing unit tests and the regression test, then judges
whether the change addresses the issue without obvious regressions. It can make
small corrections and rerun affected tests. Optional improvements are follow-ups.

## Completion and handoffs

Agents finish through Strix's `agent_finish` tool:

- Repair: `done` starts review; `blocked` stops and preserves work.
- Review: `approved` finishes; `changes_requested` resumes repair with feedback;
  `blocked` stops and explains the missing prerequisite or failed required tests.

Each agent retains its own conversation across handoffs. Test selection and
interpretation belong to the reviewer. Code checks source identity, requires a
nonempty patch, and ensures delivery matches the final workspace approved by review.
Reviewer corrections are included in that workspace. Changes after approval block
delivery; they do not automatically start another repair.

## Files and evidence

- `strix/fix/prepare.py`: routes repair and review decisions.
- `strix/fix/runtime.py`: supplies assignments to native Strix agents, routes outcomes,
  and records tool results and usage.
- `strix/fix/workspace.py`: stages source and sanitized Git metadata in the sandbox,
  then exports changes to the host's artifact mirror.

The public `strix.fix.runtime.run_isolated_fix_preparation()` entry point takes a
request and a clean Git checkout. It creates a job-owned clone and artifact mirror;
the supplied checkout is never edited. It uses the configured native sandbox
backend (Docker in OSS; registered cloud backends work for hosted callers).

The agents execute customer code only inside the sandbox. The host mirror is used
for artifact construction. Changes are saved when an agent completes or is
interrupted. Interrupted runs retain useful work without claiming approval.

The artifact contains the patch, changed files, `execution.json`,
`agent-sessions.json`, and `tool-results.jsonl`. Logs stay outside repository source.
Command records retain the output returned by native tools, including their output
limits. Agents can redirect lengthy test output to a sandbox file and inspect it
with the native tools. Command exit codes are evidence for review, not proof of
security or coverage by themselves.

## Budgets and delivery

`max_agent_turns` defaults to Strix's normal 500 turns per agent, counted across
continuations. The configurable job deadline defaults to 7,200 seconds. An optional
`max_budget_usd` applies across both agents using SDK usage estimates. The legacy
request field `max_repair_attempts` is accepted but does not control this loop.

New results use `validation_mode: agent_review`. They contain the review decision,
summary, final patch identity, and command history. The app delivers approved
results as draft PRs and includes the review and testing limitations. Historical
`native_tests` and `paired` records remain readable by the app's compatibility code;
new runs do not produce those proof structures.

## Run from the OSS CLI

Use the same configured model and Docker environment as a normal Strix scan:

```bash
strix fix --repo ./repo --finding strix_runs/my-scan/vulnerabilities.json \
  --finding-id vuln-0001 --output ./fix-result/result.json
```

A file containing one finding or a `FixCandidateV1` also works. Findings need their
recorded `fix_candidate.source_identity`; the command does not guess which revision
an old finding described. The checkout must be clean and at that recorded commit.
This first CLI version supports Git sources, not restoration of uploaded archives.

Automation and benchmarks can pass the existing request format:

```bash
strix fix --repo ./repo --request request.json --output ./fix-result/result.json
```

`--workspace` is an alias for `--repo`. `--artifact` overrides the archive path;
`--max-agent-turns`, `--timeout`, and `--max-budget` override request budgets.
Outputs are result JSON, a readable Markdown review, a patch, and the full ZIP
artifact. Without `--output`, they go in a new `strix_runs/fix-…` directory. Use an
output directory outside the source checkout to keep it clean for the next run.
Exit codes: 0 approved, 2 incomplete/blocked/stale, 1 startup or input failure,
130 interrupted. Interruptions save any checkpointed work in the ZIP archive.
Partial patches and their limitations are retained when review cannot approve.
The CLI does not push changes or publish PRs.

## Hosted integration and credentials

The hosted runner in `strix-pro` restores authorized source, calls this exact OSS
entry point, and sends the result to the app. The app owns account permissions and
publishing through the connected Git provider. Neither supplies a separate repair
or review implementation.

Fix requests cannot select environment variables from the runner. The removed
credential forwarding option accepts legacy empty lists only; nonempty lists fail
validation. No host credential names or prefix blocklists are needed. Customer test
credentials are not injected by this feature; tests needing them must report the
missing setup accurately.

## Local checks

`make test-fix-reliability` exercises the actual Strix loop and native SDK tools
with scripted model responses and local fixture tests. It covers handoffs, reviewer
corrections, blocked or interrupted work, and artifact integrity. It does not make
live model calls or evaluate patch quality; the benchmark covers those questions.

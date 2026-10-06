---
name: implementation-harness
description: Use for substantial implementation tasks that may benefit from independent subagents, especially integrations, multi-file changes, and complex bug fixes. Skip orchestration for small or tightly coupled work.
---

# Implementation harness

Use this workflow only when the task is large enough to benefit from parallel, independent work. The main agent decides whether delegation helps; keep small or tightly coupled changes in the main agent.

## Before delegating

- Inspect the repository instructions, working tree, affected code, callers, and tests.
- Split work into bounded tasks with clear outputs. Assign each subagent a task-specific specialty based on the work; do not use a fixed roster.
- Delegate only independent tasks. Avoid assigning multiple agents to edit the same files.
- If subagents are unavailable, continue in the main agent and state that delegation was unavailable.

## Two-round limit

1. **Implementation round:** subagents investigate or implement their assigned tasks; the main agent coordinates and integrates.
2. **Correction round:** an independent reviewer examines the integrated result. The main agent validates each finding and makes supported corrections, with specialist help only when useful.

Do not start a third implementation round. If issues remain after round two, report them with evidence and explain what remains unresolved.

## Independent review

Choose a reviewer specialty suited to the task. For example, an external recon-tool integration may need review of the tool's documented CLI and output, subprocess handling, and security boundaries.

The reviewer must be technically skeptical, careful, evidence-oriented, and constructive. For every finding, provide:

- the affected requirement or behavior;
- concrete evidence from the diff, repository, official documentation, or executed checks;
- impact and a specific correction, if supported.

The reviewer must check its own assumptions, distinguish confirmed defects from uncertainty, and report no findings when the evidence supports the implementation. Do not invent issues to justify a review.

## Finish

The main agent owns the final result: integrate changes, verify review claims against the code and checks, run the appropriate project validation, and summarize what changed, what was checked, and any unresolved concerns. The two-round limit applies to implementation and correction; final verification does not open another change cycle.

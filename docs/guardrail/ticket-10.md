# Ticket 10: installed pre-commit guardrail

The tracked hook loads the check runner from the Git index and executes ordinary
staged checks. Installation is explicit and repeatable; other hook configurations
and active default hooks are preserved. Linked worktree installation is refused
rather than changing shared configuration. Normal Git bypass behavior remains.

Verification: the full runner discovered 51 Python tests (48 passed, three opt-in
real-tool integrations skipped) and passed all six frontend checks, compilation
and whitespace. Public command/actual-commit tests cover failure/success, partial
staging including runner changes, documentation commits, installation conflicts,
repeat installation and terminal Ctrl+C cleanup. Standards and Spec reviews of
this ticket and the combined implementation found no outstanding issues.

The checkout activation is verified with local `core.hooksPath=.githooks`; the
installed hook is exercised before committing this ticket. Future clones run
the installer explicitly. No real capture batch or saved results were touched.
The parent specification is left open as required by the ticket workflow.

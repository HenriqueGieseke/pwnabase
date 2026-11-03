# Ticket 8: fail-fast working-file checks

Implemented the public working-file runner and explicit `--real-tools` option.
The runner uses existing compatible runtimes, shares Node through child PATH,
forces ordinary integrations off by default, keeps bytecode temporary and stops
on the first failure. Cancellation terminates the whole check process group.

Verification: six command-level fixture tests passed; full runner discovered 39
Python tests (36 passed, 3 opt-in real-tool tests skipped) and passed all six
frontend checks plus compilation/whitespace. A review regression for a stubborn
descendant reproduced cancellation failure and passed after group cleanup was
fixed. Standards and Spec rereviews reported no outstanding findings.

All guardrail tests use small synthetic repositories, so they cannot recursively
invoke the full project suite. No recovery code or real data was changed.
Next: staged snapshot checks in ticket 9; hook activation remains ticket 10.

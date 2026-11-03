# Ticket 2: safe tool execution

Implementation is ready for owner review; it is not committed or pushed.

## Change

External process execution now lives in `pwnabase.tools`. The recovery command
calls it directly for extraction, preflight, native-rule validation and recovery,
including streamed candidates. The executor's syntax tree matches the original
implementation; this ticket changes ownership rather than execution behavior.
`ToolError` lives with the executor and is shared by its callers.

The four existing executor checks moved to the agreed tool-execution seam.
Additional checks verify timeout cleanup with a cooperative candidate producer
and the bounded diagnostic tail without printing raw tool output.

## Review

Independent standards and specification reviews found no extraction regressions
or actionable standards violations. An inherited limitation remains: output is
spooled into a temporary file whose disk usage is not capped. Only the returned
diagnostic tail and in-memory progress parsing are bounded. Address disk limits
separately if needed; this extraction deliberately retains existing behavior.

## Handoff

Verification passed: all 26 Python tests, including all three real Hashcat and
extractor integrations on the CPU backend (`--device-types 1`); all six frontend
result-reader checks; Python compilation; and `git diff --check`. GPU defaults
remain unchanged; this validation does not claim GPU execution. Integration
inputs were synthetic captures and small temporary wordlists.

The remaining workflow, tool-specific command construction and storage behavior
still live in the recovery script. Candidate generation remains in its existing
module. Continue with ticket 3 for centralized storage; candidate preparation is
ticket 4. The agreed package responsibilities are not all implemented by this
first ticket.

Preserve the existing uncommitted setup and design documentation alongside this
implementation. Commit and push only after owner approval.

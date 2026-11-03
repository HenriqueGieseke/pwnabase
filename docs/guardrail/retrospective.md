# Check runner and hook retrospective

## Environment improvements delivered

The shared runner is now the fail-fast entry point for verification. A staged
whitespace failure stopped ticket 8's first commit attempt, proving that the
failure-status problem identified in the refactor retrospective is addressed.
The extra EOF blank line was fixed before a commit was made.

The tracked hook uses indexed runner code and indexed project content. This makes
partial staging meaningful even when the runner's working copy differs. Existing
runtime selection is shared with nested subprocesses without downloading or
copying dependencies into snapshots. Navigation and activation guidance live in
the check guide, with a short pointer from AGENTS.md.

## Lessons for subsequent agent work

- Use command-level fixtures before full-repository checks. Small temporary Git
  repositories exercise actual commit behavior without recursive suite execution
  or changes to real development history.
- Keep indexed bytes independent of checkout attributes. An added regression
  exposed line-ending conversion from an unstaged attribute; raw blob export
  fixed it. Preserve this check when changing snapshot implementation.
- Check descendant cancellation, not only the immediate child. Review identified
  a stubborn descendant; the regression now proves it is terminated. Terminal
  Ctrl+C and signalling only Git's parent PID are different interactions; the
  hook guide documents the actual guarantee.
- Stage and check the complete intended change before committing. The active
  guardrail now enforces the check, while the runner preserves existing output,
  index and stash state instead of attempting automatic repairs.

## Follow-up candidates

If the frontend engine expression changes beyond the currently supported stable
caret/minimum alternatives, extend runtime-selection tests and the parser together;
unsupported policy syntax already fails explicitly. Remote enforcement remains a
separate decision: the delivered guardrail intentionally preserves normal local
Git bypass behavior and adds neither CI nor branch protection.

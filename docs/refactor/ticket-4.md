# Ticket 4: candidate preparation

`pwnabase.candidates` owns profile loading, native catalog preparation, source
selection, wordlist snapshots, attempt identity, generation, streaming and
preview. The old candidate module was removed and callers/tests migrated.
Hashcat invocation remains outside candidates. Runtime CLI argument state will
be separated in ticket 5.

Verification: 23 Python checks passed; 3 opt-in real-tool checks are deferred to
the final integration milestone. Compilation and diff checks passed. Syntax-tree
comparison confirms every moved profile/generation/streaming definition is
unchanged. Existing tests cover byte safety, per-seed deduplication, fingerprints,
no eligible candidates, previews, stream completion and reruns. No algorithm or
tool invocation changed. Standards/spec review evidence is recorded on the issue.

Next: ticket 5, explicit workflow configuration/results and a thin CLI.

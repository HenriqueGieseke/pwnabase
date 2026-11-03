# Ticket 3: saved results and provenance

Storage now owns result paths, atomic JSON persistence, fingerprints, provenance
updates and completed/exhausted lookup. Workflow policy and attempt identity
remain unchanged. Existing callers/tests import storage directly.

Verification: 23 Python checks passed, with 3 opt-in real-tool checks skipped;
all 6 frontend reader checks passed; compilation and diff checks passed. Existing
batch assertions cover mixed outcomes, global skipping, changed/renamed lists,
retryable errors, unusable captures, provenance and failed atomic replacement.
No Hashcat command changed; real-tool integration was verified on ticket 2 and
will run again at the final integration milestone. Standards and spec reviews
reported zero actionable findings. All fixtures are synthetic.

Proceed to ticket 4: candidate preparation. The owner authorized automatic
commit/push of verified, reviewed tickets on 2026-11-03.

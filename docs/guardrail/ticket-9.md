# Ticket 9: isolated staged checks

Staged mode exports raw index blobs and executable modes, avoiding unstaged
checkout attributes and filters. Tests/compilation use the isolated tree while
whitespace checks use the original index. Runtime policy is staged; the selected
runtime can remain in the checkout. Nothing is stashed or rewritten.

Thirteen public-command fixture checks cover both modes, opposite partial-stage
outcomes, staged additions/deletions, raw bytes, whitespace scope, existing stash
preservation, runtime discovery, rejected index states and cancellation cleanup.
Unmerged, intent-to-add, symlink and submodule entries fail explicitly.

The full working-file runner passed: 46 Python tests discovered, 43 passed and
three opt-in integrations skipped, plus all six frontend checks. Standards and
Spec reviews found no outstanding issues. The actual staged runner is also run
before committing this ticket. No recovery behavior or real data was changed.
Next: tracked hook, installer and activation in ticket 10.

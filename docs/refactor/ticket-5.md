# Ticket 5: callable workflow

The command entry point now delegates to the CLI module. CLI validation uses the
same RunConfig validator as direct callers. RunConfig, ToolConfig and prepared
candidate settings are explicit immutable values. Workflow state/counters and
attempt diagnostics have declared types; nothing is attached to argparse objects.
The workflow returns BatchResult without parsing arguments or exiting.

Hashcat/extractor commands, preflight and authentication-record parsing now live
with tools. Workflow owns eligibility, attempts, snapshots, locks and cleanup;
storage owns result persistence; candidates owns seed preparation and generation.

The new synthetic CLI/direct-workflow check compares result files, exit codes,
record counts, permissions and rerun skipping. Existing focused checks were
migrated to their module seams without import compatibility wrappers. Standards
review identified duplicated validation; it was consolidated. Spec review found
no gaps. All 27 Python checks passed, including three real Hashcat/extractor synthetic integrations on CPU; all 6 frontend checks, compilation and diff checks passed. GPU defaults remain unchanged; GPU execution was not tested.

Next: ticket 6 cross-module compatibility evidence, documentation and overall
review. Existing datasets and saved results remain untouched.

# Handshake batch recovery

## Local result viewer: agreed requirements

Use Vue/Nuxt for a local browser interface resembling a dark spreadsheet, with taller rows and fixed column headers. The first version is read-only: no editing/deleting JSON and no recovery process controls.

Each JSON file is one row, with directory-specific columns and a details panel containing nested data and raw JSON. Recovered passwords are shown directly in the complete table.

Refresh every five seconds and provide manual refresh, preserving the active tab, filters, selection and scroll position. Run separately from the recovery batch, read completed JSON only, and never acquire its batch lock or modify recovery state. Limit refresh work using cached metadata and changed-file reads. Tolerate disappearing files and both missing and null rules metadata in older results.

Include exactly five tabs initially: `complete`, `exhausted`, `no-usable-handshake`, `tool-error`, and `rules`. Exclude internal runtime and configuration directories. Keep results outside the frontend's public assets and serve data through a read-only API bound to localhost.

The exhausted tab includes all wordlist subdirectories, with a wordlist column and filter. Keep separate attempt files as separate rows. The rules tab shows one row per catalog file, with rule objects in the details panel.

Provide active-tab text search, sortable columns, and pagination with 50 rows per page. Default result ordering is newest first. Preserve controls during refresh. Build the frontend in a separate subdirectory, using a compatible Node runtime without replacing the host runtime during the ongoing batch.

## Agreed scope

Build a manually invoked Python 3 script for local, authorized offline recovery using Hashcat and hcxpcapngtool. Process captures sequentially using `SambaTu/SambaTu.txt` by default. Wardriving imports and a database are deferred.

Preserve original files in `handshakes/`. Extract authentication records and track outcomes per record, allowing one capture to have both recovered and exhausted records.

## Outputs

Write structured JSON result files to:

- `complete/`: successful recoveries only, including recovered passwords.
- `exhausted/SambaTu/`: records exhausted against the SambaTu wordlist.
- `no-usable-handshake/`: readable captures yielding no usable authentication records.
- `tool-error/`: failures, with diagnostic information.

Retain source references, capture content fingerprints, BSSID, and SSID for provenance and later correlation. Only successful result files contain recovered passwords.

## Reruns and failures

Fingerprint captures and wordlist contents. Skip successful records and records already exhausted against the same wordlist contents. Changing wordlist contents permits a new attempt even if the filename is unchanged. Retry tool errors on the next invocation.

Check shared dependencies before processing. Individual capture errors must not stop subsequent captures. Missing shared requirements, including an unavailable compute backend, stop execution with a clear explanation.

## Candidates and interruptions

### SSID-derived mode

The same SSID profile can be applied to file-wordlist entries using
`--ssid-rules` (SambaTu by default) or by selecting an SSID-profile JSON with
`--rules`. This is distinct from `--ssid`, which continues to use each network's
own name. Stream hex-encoded candidates to Hashcat with bounded buffers and
per-entry generation/deduplication; do not materialize an expanded wordlist.
Record the actual wordlist, profile and streaming-generator identity, with a
separate attempt filename identity. Preserve completed results and classify
generation failures as errors. Exhaustion requires the source to finish; early
recovery may record partial generation counts. Keep this mode opt-in because
the profile can greatly multiply work, and stdin totals/ETA are unavailable.

Add a separate opt-in candidate-source mode using only the SSID associated with each authentication record. Preserve the default wordlist workflow. Preserve the exact SSID bytes already stored in `ssid_hex`; the display string can contain replacement characters and must not silently become the seed.

Agreed transformation coverage:

- Preserve the untouched SSID. Treat spaces, hyphens, underscores and dots as word boundaries for generated variants; join words using spaces, hyphens, dots, underscores or no separator.
- For valid UTF-8 text, generate accented and accent-free forms using Unicode-aware casing. Case variants: original, lowercase, uppercase, title case, inverted first character, and lowercase first character with uppercase remainder.
- Three substitution profiles: unchanged; numeric (`a→4`, `e→3`, `i→1`, `o→0`); symbolic (`a→@`, `e→3`, `i→1`, `o→0`, `s→$`, `u→v`). Apply substitutions case-insensitively.
- Optional numeric suffix: none, numbers 0–99, or years 2000–2026. Follow with optional punctuation: none, `!`, `@`, `#`, or `.`. Ranges must be explicit in JSON rather than changing with the calendar.
- Combine these families, generate distinct candidates in Python and let Hashcat test them.

Agreed interface and behavior:

- `python3 recover.py --ssid` uses the dedicated `rules/ssid.json` profile. `--rules` can select another SSID profile; `--ssid` and an explicitly supplied external `--wordlist` are mutually exclusive. The existing default wordlist command remains unchanged.
- Invalid UTF-8 SSIDs retain their exact original bytes as the only candidate; skip character-based transformations and explain the limitation in logs. Use byte-safe candidate input, never the lossy display string.
- Report generated, duplicate, rejected-length and eligible candidate counts without printing candidates during recovery. `--preview-ssid "Minha Rede"` explicitly previews caller-supplied text without reading captures or running recovery.
- Store exhausted SSID-derived attempts in `exhausted/ssid/`. Record source type, exact source identity, profile identity and generation identity so retries cannot collide with file-wordlist attempts. Profile behavior changes permit a new attempt; descriptive metadata changes alone do not.
- Classify zero eligible candidates as `no_eligible_candidates`, not a tool error. Retain the evidence in the SSID exhausted directory. Previously recovered records remain globally skipped.
- Update the viewer's source labels and details to distinguish SSID-derived attempts from external wordlists, while retaining compatibility with historical results.

Try wordlist entries as supplied by default. Optional `--rules` selects a versioned JSON catalog of rule objects (stable ID, description, native Hashcat expression). Compile the ordered expressions to a temporary native rule file. The basic catalog contains the eight agreed introductory transformations. Fingerprint the ordered expressions alongside wordlist contents for exhaustion identity; retain catalog metadata in results. Successful records remain globally skipped.

Ctrl+C stops the batch cleanly and preserves completed results. Write results atomically. Unfinished records remain eligible for another attempt, starting from the beginning in v1.

Skip unchanged captures previously classified as having no usable handshake. Provide `--retry-unusable` to request another extraction attempt; changed captures are automatically eligible.

## Modular refactor: agreed direction (planning)

Refactor the Python recovery workflow incrementally for maintainability and future imports. Preserve existing commands, defaults, result formats and filenames, skip/retry decisions, and interruption behavior. Keep one local application with Python modules behind `python3 recover.py`.

Database migration, wardriving imports, frontend job controls, and parallel recovery remain separate features. The longer-term product is an application accepting Pwnagotchi and wardriving uploads with a shared collection of observations and recovery results. The Dell OptiPlex will hold the central database, the current desktop will perform heavy recovery work, and the notebook will serve as a smaller mobile lab. Recovery workers should eventually be independent of the machine used to upload or browse. Network protocols, offline synchronization, database technology, and scheduling remain undecided and outside this refactor.

Follow the agreed workflow: grill-with-docs, to-spec, to-tickets, implement one ticket at a time, code-review, then retro. Begin implementation with tool execution. Use codebase-design throughout; clear context between completed implementation tickets once their outcomes are recorded. Do not commit or push implementation changes before user approval.

The user confirmed that the recovery batch has stopped; an isolated checkout is not required solely to protect that batch. Continue using synthetic fixtures for development and preserve existing local data.

### Module responsibilities and compatibility

Introduce a `pwnabase/` Python package, retaining `recover.py` as the small entry point for the existing command. Group responsibilities into CLI (options and startup), workflow (captures, attempts, skips and failure handling), tools (subprocess execution, extraction and recovery), candidates (wordlists, profiles and streaming), and storage (result files, provenance and saved attempt history). These responsibilities do not require one file or one class each; keep interfaces small and place complexity behind them.

Use explicit configuration and attempt results instead of attaching runtime state to CLI arguments. The workflow must be callable without constructing command-line arguments. Storage owns paths, atomic writes and lookups; the workflow owns decisions to skip, retry or recover. Retain file storage in this refactor without implementing a database adapter or network worker protocol.

Compatibility covers the CLI and stored results, including the existing viewer's ability to read them. Internal Python functions and tests may move without preserving old imports through forwarding wrappers. Preserve default GPU selection, candidate behavior and byte handling, attempt identities, locks, completed-result retention, failure isolation, cancellation behavior, private file handling and informative logs. Avoid extra per-candidate logging or processing overhead.

Use existing tests and focused additional checks for risky behavior such as cancellation, candidate stream failures and retry identity. Use synthetic data and real-tool checks at relevant milestones; do not launch recovery against existing local captures as part of verification. Document discovered pre-existing bugs separately and defer fixes unless they block safe progress; surface any necessary behavior change explicitly.

Offline notebook operation and synchronization remain future design questions. The modular workflow must not assume that the notebook always has connectivity to the Dell.

## Repository checks and commit guardrail (planning)

Build one fail-fast repository check runner and a local pre-commit hook. Keep
GitHub Actions, branch protection and changes to the direct-to-main workflow out
of this first version. Ordinary checks require Python compilation, ordinary
Python tests, frontend result-reader tests and whitespace checks. Stop on the
first failed check; hook invocation must block the commit on failure.

Real Hashcat/extractor integrations require an explicit option and are excluded
from automatic pre-commit execution. Missing required dependencies are failures
with actionable messages. Checks must not install/download dependencies, format
code, change staged content, or automatically fix files. Use synthetic fixtures
and preserve real captures, wordlists, runtime state and saved results.

The pre-commit hook tests a temporary export of the Git index so partially staged
files are checked as they will be committed. Do not stash or rewrite the working
tree or index. Track the hook in the repository and provide an explicit installer
that enables it for this checkout; stop rather than overwrite an existing
different hook configuration.

Prefer an existing project-local compatible Node runtime, otherwise a compatible
Node from PATH. Use the selected runtime consistently, including Node subprocesses
launched by Python tests. Never download a runtime during checks. Support Linux
only in this version, matching the project's existing POSIX test dependencies.

Expose `./scripts/check` for current working files and `./scripts/check --staged`
for the staged snapshot. The hook always uses staged mode. Working-file mode
reports staged and unstaged whitespace errors; staged mode checks staged
whitespace only, allowing unrelated unfinished edits to remain in the working
tree. Run all required fast checks for each hook invocation. Ignore an inherited
RUN_REAL_TOOLS setting for ordinary checks; enable real integrations only through
an explicit manual option.

After implementation tests pass, install and verify the hook in this checkout.
Future clones enable it explicitly. Keep normal Git hook bypass behavior and
document the local enforcement limit; do not add a custom bypass mechanism.
On interruption or failure, stop checks, abort the commit when invoked as a hook,
and clean up temporary snapshots. Provide clear stage/failure output and preserve
the failing command's useful diagnostics.

## Interrupted transformed-wordlist attempts (investigation)

This section records an earlier investigation and its design decisions. Resume
and workload controls have since been implemented; see the README for current
behavior.

A synthetic workflow reproduction confirms that an interrupted streamed
wordlist-profile attempt restarts at its first candidate chunk. Two runs both
returned interruption code 130 and replayed the same first chunk. Completed
outcome files are retained; there is currently no mid-attempt checkpoint. This
matches the original interruption contract, which the modular refactor preserved.
The capture traversal counter starting at one alone does not prove that completed
records are being retried; saved outcomes are checked inside capture processing.

The full default profile has at most 115,201 generated combinations per seed.
The current SambaTu input contains 2,140,469 entries, giving an upper bound of
246,584,169,269 combinations per authentication record before per-seed
deduplication and eligibility filtering. Three invented seeds generated in about
0.04–0.05 seconds each locally, with substantially fewer eligible unique
candidates. These measurements do not establish actual wordlist-wide generation
cost, overnight runtime or GPU throughput.

Resume semantics, workload controls and progress visibility are being designed.
Any checkpoint must represent confirmed tested work, not merely generated or
buffered candidates, so interruption cannot skip untested candidates. No recovery
implementation or live batch was changed during this investigation.

Agreed goals: add durable resume for transformed-wordlist attempts, add an
explicitly selected light profile near 1,000 combinations per source word while
retaining the full profile, and improve live progress/checkpoint visibility plus
startup workload estimates. Aim for a checkpoint roughly every minute, accepting
replay of one unfinished batch; measure overhead before selecting batch size.
Resume automatically only when authentication record, wordlist contents, profile
behavior and generator version match. Other identities start separate attempts.
A stopped position within an unconfirmed batch cannot be promised as an exact
restart position. Earlier interrupted runs without checkpoints cannot recover
their discarded partial progress retroactively.

Treat approximately 1,000 combinations per source word as a maximum expansion
budget, with fewer unique eligible candidates after filtering and deduplication.
Do not generate the full profile and truncate or pad with duplicates. Prioritize
original/lowercase/initial-capital forms, curated numeric suffixes, limited years,
and a small selection of punctuation and leet substitutions. Keep extensive
separator and unusual case permutations in the full profile.

Provide human-readable live terminal updates with clear stage headings, blank
lines between captures/attempts, readable count units, and distinct generated,
confirmed-tested and checkpointed progress. Avoid per-candidate output and keep
logging overhead bounded. A read-only --status command should inspect saved
progress from another terminal without acquiring the batch lock, running tools,
or stopping the active run. Defer frontend progress controls.

Preserve unreadable checkpoints and report an error for the affected attempt,
continuing other inputs. Starting that attempt over requires an explicit action.
Use bounded temporary candidate files per batch and commit progress only after
Hashcat confirms that batch finished; never persist the entire expanded list.
Clean temporary batches after use while retaining durable confirmed checkpoints.

Always print a startup workload estimate and offer an estimate-only option.
Do not introduce a mandatory confirmation prompt. Clearly distinguish theoretical
upper bounds, sampled estimates and measured throughput; show runtime as unknown
until there is sufficient evidence to estimate it.

Support --ssid-rules light as the short explicit light-profile selection. Keep
bare --ssid-rules equivalent to the existing full profile. Both transformed
wordlist profiles resume automatically from matching confirmed checkpoints when
the same command is rerun. Provide --restart-incomplete only as a deliberate
override for matching unfinished attempts, preserving completed outcomes and a
backup of prior checkpoints. It is not required for ordinary resume.

Keep the light profile as readable, versioned JSON with fixed behavior and
ordering. Research and aggregate local findings inform its curated defaults;
newly recovered passwords must not automatically mutate the profile. Retain
behavioral fingerprints so descriptive edits alone do not reset an experiment.

The user authorized local aggregate analysis of recovered passwords as a design
input and research into published breach-password variation patterns. Never put
recovered values, byte strings, identities or individual examples into reports,
web queries, profiles or version-controlled documentation. Research notes and
selection-bias limitations are in docs/research/light-profile-inputs.md.

## Batch status tab (decisions in progress)

This section records the original design discussion. Batch status and run
history have since been implemented; see the README for current behavior.

Add a read-only local frontend tab showing the current or most recent batch.
Starting and stopping batches remains a terminal operation. The user will stop
the current batch before implementation; live monitoring applies to subsequent
runs. A stale update is shown as unknown with its last update time, rather than
being represented as certainly running or cleanly stopped.

Within the tab, automatically group runs by batch configuration. Changed wordlist
contents or transformation behavior create a new, numbered subtab even when a
name is unchanged; renaming or moving unchanged wordlist contents does not.
Repeated runs of a matching configuration share a subtab. Show capture progress,
the current authentication record, wordlist position, and transformation counts;
show percentages only where a reliable total exists. Distinguish generated,
Hashcat-confirmed and checkpointed candidates, and do not claim exact progress
inside a source word when it cannot be measured reliably.

Retain past runs for later comparison, initially loading the latest 20 with a
control to load older runs. Retain compact, sanitized event logs per run,
initially showing the latest 200 events with a control to load earlier events.
Do not persist raw Hashcat output or expose candidate words or passwords in logs.
Run history can support future comparison of configurations; sanitized logs alone
do not identify the precise mutation that recovered a password. Further storage,
retention and telemetry details are still being discussed.

Record meaningful events rather than periodic numeric updates; keep live progress
separately to limit log growth. Display starting, running, completed, interrupted,
failed and unknown states with the last-update time. Show Hashcat speed and ETA
when available, labeling them as applying to its current invocation. Retain
configuration identity, outcome and candidate counts, and timings for future
comparisons; detailed attribution of successful transformations is deferred.
Support plain wordlists, SSID-only attempts, native Hashcat rules, and full or
light transformed-wordlist profiles, hiding inapplicable progress fields.
Automatically select an active configuration unless the user is inspecting an
older run. Refresh approximately every five seconds and show unknown after about
30 seconds without a heartbeat. Display the current capture filename, SSID and
BSSID, and recovered, exhausted, skipped, unusable and failed outcome counts.
Each execution, including a checkpoint-resumed execution, is a separate run
within its configuration and reports its own outcomes, including skips. Events
include concise sanitized errors when safe, or a general error category and
affected context when raw diagnostics are unsafe. Store private status and run
history outside Git and retain them across frontend and machine restarts.
Show a compact summary and progress bars above recent logs and selectable run
history, using the existing dark style and larger rows. History starts with
batches run after this feature is installed. Retain it until a future cleanup
feature is available and show its approximate storage size.
For native Hashcat rules, show the selected rule set and reliable reported
progress, with current-rule or rule-total progress marked unknown when it is
unavailable. For transformed wordlists, show the profile, source-word position
and generated, confirmed and checkpointed candidate counts.

## Portfolio readiness

Prepare Pwnabase for an employer to clone, understand, and explore without a
GPU or real wireless captures. Keep the GitHub repository private until the
owner separately chooses to change its visibility.

Include tracked placeholders for handshakes/, complete/, exhausted/,
no-usable-handshake/, and tool-error/ so a fresh clone has the expected
directories. Keep all actual inputs and results inside them ignored, including
nested data. Verify ignore rules with fictional paths without staging local
captures or results. Preserve existing protections for other private data. On
batch startup, automatically make placeholder-only result directories private;
preserve permissions on directories containing existing user data. Report a
filesystem error if a placeholder-only directory cannot be secured.

Add viewer controls beside Hide duplicates to hide passwords and SSIDs. Both
privacy controls default to hidden when no valid preference exists. Apply them
throughout visible tables, tooltips, details, raw JSON and batch views, including
password and SSID byte representations and capture filenames and paths that may
contain network names. Masking is a display aid: local API responses and result
files can still contain sensitive data. Store only toggle preferences in the
browser, never result data or identifying values. Persist preferences across
batches, reloads and viewer restarts. Password and SSID visibility are global;
Hide duplicates retains its separate preference for each sheet.

Provide an isolated, clearly labeled fictional dataset and a separate demo
launch path that does not touch normal results or require Hashcat, an extractor,
captures, a wordlist, or a GPU. Frontend dependencies remain necessary. Create
a README screenshot solely from the fictional demo with both privacy controls
enabled. Lead the README with the project purpose, demo, quick start, current
limitations, and links to the study guide and detailed setup.

Add a Linux GitHub Actions workflow for the existing fast repository checks
with synthetic test data. Optional real-tool integration remains explicit and
local. Verify privacy controls, preference persistence, accessible labels,
directory ignore behavior, demo isolation and the documented setup. Add the
MIT License with copyright attributed to 2026 Pwnabase contributors.

Develop this work through a specification and ordered tickets, then implement
and review in small steps. The agreed priorities are safe directory scaffolding,
viewer privacy and preferences, the fictional demo and presentation, and CI and
licensing; refine dependencies when the tickets are written.

## Development prerequisite

Install and verify Hashcat locally before starting implementation, so development and testing can use the real tool. Install hcxpcapngtool for capture extraction as well. Synthetic-only validation is insufficient for the requested development workflow.

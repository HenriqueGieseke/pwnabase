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

## Development prerequisite

Install and verify Hashcat locally before starting implementation, so development and testing can use the real tool. Install hcxpcapngtool for capture extraction as well. Synthetic-only validation is insufficient for the requested development workflow.

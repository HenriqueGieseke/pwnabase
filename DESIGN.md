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

Try wordlist entries as supplied by default. Optional `--rules` selects a versioned JSON catalog of rule objects (stable ID, description, native Hashcat expression). Compile the ordered expressions to a temporary native rule file. The basic catalog contains the eight agreed introductory transformations. Fingerprint the ordered expressions alongside wordlist contents for exhaustion identity; retain catalog metadata in results. Successful records remain globally skipped.

Ctrl+C stops the batch cleanly and preserves completed results. Write results atomically. Unfinished records remain eligible for another attempt, starting from the beginning in v1.

Skip unchanged captures previously classified as having no usable handshake. Provide `--retry-unusable` to request another extraction attempt; changed captures are automatically eligible.

## Development prerequisite

Install and verify Hashcat locally before starting implementation, so development and testing can use the real tool. Install hcxpcapngtool for capture extraction as well. Synthetic-only validation is insufficient for the requested development workflow.

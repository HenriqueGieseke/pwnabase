# Local result sheets

A read-only Nuxt/Vue viewer for Pwnabase JSON data. The dark workbook has five
directory tabs, 64-pixel rows, sortable columns, search, 50-row pages and a details
panel with raw JSON. Passwords are hidden by default in the complete sheet,
details, tooltips and raw JSON. Use **Hide passwords** to reveal them; non-UTF-8
passwords are displayed using their exact hexadecimal bytes. This controls the
display, not access to local result files or API responses.

From the project root, run:

```bash
node frontend/start.mjs
```

For the normal viewer, open **http://127.0.0.1:3000**. Initial startup requires internet access to install
dependencies. Nuxt 4.6.0 requires a newer Node patch than the host's 22.22.1; the
launcher installs Node 22.22.3 inside `frontend/.runtime/` if necessary. It does
not replace system Node. Dependencies, caches and build artifacts stay in the
frontend directory. After setup, the same command starts the app again.

To explore separately with fictional data, run `node frontend/demo.mjs` instead
and open the local URL printed by Nuxt. The demo creates a temporary data
directory and removes it on exit; it does not read your results or require
Hashcat, capture files, a wordlist, or a GPU. Frontend dependencies and a local
Node runtime may still need installation.

The viewer is a separate process and can run while recovery continues. It never
starts/stops Hashcat, acquires the recovery batch lock, or writes result JSON.
Ctrl+C in the viewer terminal stops only the viewer. Keep the recovery batch in
its own terminal.

Only these directories are readable through the API:

- `complete/`
- `exhausted/`, including one level of wordlist subdirectories
- `no-usable-handshake/`
- `tool-error/`
- `rules/`

Every JSON file is a separate row. Exhausted attempts remain separate even when
they refer to the same network or a later recovery exists. Filter that sheet by
wordlist. The rules sheet has one row per catalog, with individual transformations
in the details panel. Newest results appear first; rules use file modification
time when no result timestamp exists. All tabs have independent controls.

Enable **Hide duplicates** beside search to show one row per identical SSID,
BSSID and password combination in the active sheet. Filtering happens before
pagination and retains the first matching row in the selected sort order.
The checkbox defaults to off and retains its setting per tab. Password visibility
and each tab's duplicate setting are saved in browser storage across restarts;
the browser stores the settings, not the passwords.
Use **Hide SSIDs** to conceal network names, their byte representation, and
capture filenames and paths in the viewer, including batch status. It is enabled
by default and its setting is also saved locally. Like password hiding, this is
display masking; the local files and API retain their data.
Search text is also visually masked while either privacy control is enabled,
because a search can contain a password or network name.
Files without network identifiers stay separate, and hexadecimal password bytes
are distinguished when the password cannot be displayed as text. Source files
are never deleted or merged.

The Candidate source column and exhausted-sheet filter distinguish external
wordlists from **SSID** experiments. SSID outcomes include `candidates_exhausted`
and `no_eligible_candidates`; both are valid completed outcomes. File details
show generation counts when present, and the rules sheet displays SSID profile
stages and their configuration alongside ordinary native rule catalogs.
When an SSID profile is applied to a wordlist through `--ssid-rules`, the source
remains the actual wordlist. Its rule-set column identifies the selected profile,
and generation details show seeds, non-UTF-8 entries and source completion where
available. Partial generation counts after early recovery are not tested totals.

The active sheet refreshes every five seconds. Metadata is checked sequentially,
and unchanged JSON contents are reused from memory. Updates preserve filters,
sort, page, selected file and scroll, clamping the page if files disappear. Files
removed during refresh are tolerated; invalid JSON appears as an error row rather
than breaking the sheet. A missing directory is an empty sheet. Files over 5 MB
are reported as unreadable. Both legacy files without rules metadata and newer
files with null or populated rule metadata work.

Source files stay outside public assets. The server binds to `127.0.0.1` and
rejects non-local hostnames and cross-origin API requests. Internal directories
and symlinks are excluded. Do not expose this password-bearing viewer through a
public reverse proxy.

For a fixture dataset, set `PWNA_DATA_ROOT=/absolute/path` before starting the
launcher. API responses are not cached by the browser. `GET /api/sheets` accepts
`tab`, `search`, `wordlist`, `sort`, `direction`, and `page`; with `tab` and `id`
it returns one file's details. IDs are opaque identifiers from the sheet response,
not filesystem paths. No write endpoints exist.

Run dependency-free filesystem tests:

```bash
node frontend/tests/sheets.test.mjs
```

With a compatible Node runtime and installed dependencies, build with
`npm run build` inside `frontend/`. If using the launcher's local Node runtime,
prepend `frontend/.runtime/node_modules/node/bin` to PATH before invoking npm
from the project root (or the corresponding `.runtime/...` path inside frontend).

The filesystem tests cover synthetic results, catalog details, search, sorting,
pagination, historical attempts, atomic replacement, deletion, malformed input,
missing directories and excluded symlinks/internal directories.

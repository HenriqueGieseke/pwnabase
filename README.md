# Pwnabase

The local spreadsheet viewer is started separately with `node frontend/start.mjs`.
Open `http://127.0.0.1:3000`; recovery can keep running in its own terminal.
See [viewer setup and behavior](frontend/README.md).

Local batch password recovery for authorized WPA/WPA2 captures. Python 3.10+ orchestrates `hcxpcapngtool` and Hashcat mode 22000; no Python packages are required.

## Run

On Ubuntu, install the tools and a CPU compute backend:

```bash
sudo apt install hashcat hcxtools pocl-opencl-icd
```

From this directory:

```bash
python3 recover.py --check
python3 recover.py
```

Captured traffic, recovered results, local state, credentials, and password
datasets are excluded from Git. After a fresh clone, create `handshakes/` and
install the wordlist separately (or supply your own with `--wordlist`):

```bash
git clone https://github.com/HideMeBr/SambaTu.git SambaTu
mkdir -p handshakes
```

Keep newly imported wardriving data in a dedicated ignored data directory; JSON
and CSV filenames are not globally ignored because source catalogs and fixtures
use these formats too.

`--check` runs a real recovery against a generated, known-password PMKID. It does not process your captures. The first run can take longer while OpenCL kernels compile. The default backend is the GPU. Recovery has been verified on the RX 580 through Mesa Rusticl in the desktop terminal, and on the Ryzen CPU through PoCL.

The default batch reads `.pcap`, `.pcapng`, and `.cap` files directly inside `handshakes/`, using `SambaTu/SambaTu.txt`. Paths are relative to the script's location, so invoking it from another directory also works. Processing is sequential and original captures remain untouched. A large wordlist on a CPU can take considerable time across many records.

Alternate inputs and output location:

```bash
python3 recover.py --handshakes /path/to/captures --wordlist /path/to/list.txt --output /path/to/results
python3 recover.py --retry-unusable
python3 recover.py --device-types 1
```

`--device-types` selects OpenCL CPU (`1`), GPU (`2`, the default), or both (`1,2`). The script automatically sets `RUSTICL_ENABLE=radeonsi` for its child processes unless you already supplied a value; no environment prefix is needed. `--hashcat` and `--extractor` accept alternate executables. Password candidates are used literally: Hashcat's `$HEX[...]` wordlist interpretation is disabled. Mutation rules are applied only when `--rules` is supplied; no brute-force fallback is applied. Hashcat rejects candidates outside mode 22000's supported password lengths; exhaustion covers the eligible candidates in the supplied wordlist.

## Results

| Directory | Contents |
| --- | --- |
| `complete/` | One JSON file per successfully recovered authentication record |
| `exhausted/SambaTu/` | One JSON file per record and wordlist fingerprint when no candidate succeeds |
| `no-usable-handshake/` | One JSON file per readable capture yielding no usable authentication material |
| `tool-error/` | JSON diagnostics for failed captures or authentication records |
| `.pwnabase/` | Capture-to-record provenance, compute caches, lock, and temporary working files |

For another wordlist, the exhausted directory uses its sanitized filename without its extension. The full SHA-256 wordlist fingerprint is part of each exhausted result filename, so different versions of the same list remain distinct.

Result JSON uses `schema_version: 1` and includes source paths and SHA-256 fingerprints. Authentication results include the extracted mode 22000 record, BSSID, client address, SSID text and exact SSID bytes (`ssid_hex`), and wordlist identity. Successful results additionally contain `password` and `password_hex`; non-UTF-8 passwords have `password: null` and remain recoverable exactly from `password_hex`. Passwords are not printed to the terminal or persisted in failure diagnostics or a Hashcat potfile. Result files are created with owner-only permissions.

Each extracted authentication record has its own outcome. A capture containing multiple networks can therefore contribute to several directories. Historical exhaustion results remain after later recovery. Identical records from several captures share results, and their source references are retained.

On reruns:

- Successful records are skipped regardless of the selected wordlist.
- Exhausted records are skipped for identical wordlist contents, including a renamed wordlist. Changed contents trigger another attempt.
- Unchanged unusable captures are skipped unless `--retry-unusable` is supplied. Recheck these after upgrading the extractor if needed.
- Tool errors are retried automatically, and their corresponding error files are removed after a successful retry.

Each batch snapshots its wordlist and each capture before processing. Original captures and wordlists are never changed. Stop with Ctrl+C to terminate the active tool and preserve completed results; an unfinished attempt starts again from the beginning next time. Results are written atomically, and a lock prevents concurrent batches sharing one output directory.

Missing shared dependencies or an unusable compute backend stop the batch during preflight. Individual extraction or recovery errors are recorded and processing continues. A failure to write the output itself can prevent further processing.

Exit codes: `0` means the batch completed without tool errors (exhaustion and unusable captures are valid outcomes); `1` means individual tool errors occurred; `2` means startup or shared infrastructure failed; `130` means interrupted.

## Validation

```bash
python3 -m unittest discover -s tests -v
RUN_REAL_TOOLS=1 python3 -m unittest discover -s tests -v
```

The real-tool integration test generates synthetic wireless packets, extracts PMKID and EAPOL records, recovers known passwords, exhausts a tiny wordlist, handles corrupt and empty captures, and verifies rerun skips. It uses a temporary directory and does not access `handshakes/`.

The agreed scope is recorded in [DESIGN.md](DESIGN.md), with domain terms in [GLOSSARY.md](GLOSSARY.md). Wardriving imports and a database are deferred.

## Terminal progress

Normal output explains extraction, PMKID/EAPOL counts, record identities, results,
skip reasons, result locations, and elapsed time. Long recovery attempts report
Hashcat progress and speed approximately every 10 seconds. ETA is an estimate;
startup and kernel compilation may initially produce only a waiting message.
Passwords and candidate strings are excluded from progress output.

Use `--progress-interval 30` for fewer periodic messages, or
`--progress-interval 0` to disable periodic updates while retaining outcomes.
Logging is terminal-only, with no extra wordlist scans or GPU queries during recovery.

## Optional mutations

Wait for the current batch to finish (or stop it cleanly) before starting another
batch in the same output directory. The plain command stays unchanged:

```bash
python3 recover.py
python3 recover.py --rules rules/basic.json
python3 recover.py --check --rules rules/basic.json
```

The JSON catalog has `schema_version: 1`, an `id`, a `description`, and an ordered
`rules` array. Each rule object has a unique `id`, a `description`, and an
`expression` in Hashcat's native rule language. IDs contain letters, numbers,
underscores or hyphens. Expressions are single printable ASCII lines. Hashcat
validates their syntax before captures are processed. The temporary native rule
file is generated from the catalog; the original wordlist stays unchanged.

The basic catalog contains eight independent transformations. For an invented
input `familia123`, they produce:

| Rule | Candidate |
| --- | --- |
| original | `familia123` |
| lowercase | `familia123` |
| uppercase | `FAMILIA123` |
| capitalize | `Familia123` |
| append_exclamation | `familia123!` |
| append_one | `familia1231` |
| append_123 | `familia123123` |
| capitalize_append_exclamation | `Familia123!` |

Each rule starts from the original candidate. Duplicates can occur; eight rules
mean up to eight candidate transformations per word, before length rejection.
Rules can substantially increase recovery time; they do not guarantee success.

Exhausted mutation attempts stay under the wordlist-named directory, with the
ordered-expression SHA-256 appended to the filename. Plain attempts retain their
existing filenames. Changing descriptions or IDs alone does not trigger retries;
changing expressions or their order does. Earlier plain exhaustion does not skip
mutated attempts, and previously recovered records remain skipped for all rule
sets. Historical exhaustion files remain as evidence of prior attempts.

Result JSON includes `rules: null` for new plain results, or the full rule catalog,
its source path, and expression fingerprint for mutation results. Older results
without this field remain compatible. This records the successful rule set,
not which individual transformation matched. The backend self-test always uses
a known plain candidate independently of your chosen rules; `--check --rules`
also validates the catalog syntax.

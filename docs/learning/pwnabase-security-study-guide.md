# Pwnabase: a practical security study guide

This guide follows an authorized Wi-Fi capture through Pwnabase. It explains the security ideas behind the work, points to the code, and provides exercises using fictional or synthetic data. Run commands from the repository root. For setup and operational details, see the [README](../../README.md) and [command cheatsheet](../../CHEATSHEET.md).

## Learning with AI

Pwnabase is a learning project built with AI assistance. The project goals and design decisions were developed through discussion; AI helped investigate, implement, review, and document the work. The examples below connect explanations to source code and reproducible checks so a reader can inspect the evidence and develop their own understanding.

## 1. From a Wi-Fi exchange to a capture

When a client connects to an access point, they exchange authentication messages over radio. A Pwnagotchi can record wireless packets containing handshake material in a PCAP file; Pwnabase starts with that file. Pwnagotchi's [project documentation](https://github.com/evilsocket/pwnagotchi) describes its capture process. Radio bands, channels, and signal analysis are background to this workflow and are outside Pwnabase's current implementation.

```text
Wi-Fi devices → packet capture → hcxpcapngtool → authentication record
             → candidates → Hashcat → outcome files → local viewer
```

A **capture** is a collection of packets, not a password. A capture can contain multiple usable records or none. A **handshake** is an authentication exchange; a PMKID is a distinct authentication artifact. Both can supply material for offline password verification under supported conditions.

**Exercise:** Read [`extract_capture`](../../pwnabase/tools.py) and follow the `snapshot`, `extracted`, and `records` variables. Observe that the extractor receives a snapshot and produces a separate output file.

## 2. Extraction and the 22000 record

`hcxpcapngtool`, from hcxtools, extracts supported authentication material from a capture. Hashcat's [22000 format documentation](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2) describes the corresponding verification format. Pwnabase delegates extraction to the tool:

```python
code, diagnostic = run_tool([extractor, '-o', str(extracted), str(snapshot)],
                            env, work)
```

In [`pwnabase/tools.py`](../../pwnabase/tools.py), `-o` selects the extracted record file. `parse_record` validates its fields and identifies `WPA*01` as PMKID and `WPA*02` as EAPOL material. It preserves the SSID's exact bytes as hexadecimal as well as a display string. Bytes matter because a displayed replacement character cannot reproduce an invalid UTF-8 byte sequence.

**Exercise:** Open `parse_record` and trace how `ssid_hex` and `ssid` are made. Compare their purposes with the [glossary](../../GLOSSARY.md) definitions of capture, handshake, SSID, and BSSID.

## 3. Verification is not decryption

An offline attempt starts with recorded authentication material and a list of candidate passwords. For each candidate, the verification tool performs calculations and checks whether the result matches the recorded artifact. A match identifies a candidate consistent with that record; it does not mean the password was stored in the capture as readable text or that a hash was reversed.

An exhausted wordlist means only that its eligible candidates did not match. Another wordlist or different rules may produce a different outcome. Pwnabase separates successful, exhausted, unusable, and tool-error results; see [result directories](../../README.md#results).

**Exercise:** Run a preview with fictional text. This generates examples without processing captures:

```bash
python3 recover.py --preview-ssid "Minha Rede" --preview-limit 12
```

Observe how transformations produce candidates. A generated candidate is not necessarily a tested candidate, and neither is a recovered password until verification succeeds.

## 4. Cryptography in the synthetic self-check

The project creates a known PMKID record to check that the installed tools and compute backend can actually recover a known test password. The following excerpt is from [`synthetic_record`](../../pwnabase/tools.py):

```python
pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
pmkid = hmac.new(pmk, b'PMK Name' + ap + client, hashlib.sha1).digest()[:16]
```

PBKDF2 derives a key from a password, a salt, an iteration count, and an output length. In this WPA example the SSID supplies the salt, the count is 4,096, and the derived pairwise master key is 32 bytes. HMAC uses a key and a message to produce an authentication value; here the code computes an HMAC-SHA1 over a label and two addresses, then keeps its first 16 bytes for the synthetic PMKID. [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018) explains PBKDF2; [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) explains HMAC.

These parameters reproduce this specific protocol test. They are not a recommendation for designing a new password storage system. Hashing, key derivation, authentication, and encryption have different purposes.

**Exercise:** Run the self-check:

```bash
python3 recover.py --check
```

It uses a generated record and a known test password, not your captures. On success it reports that dependencies and mode 22000 recovery were verified. The first run may compile kernels. To exercise the CPU backend instead, add `--device-types 1`.

## 5. Wordlists, rules, and compute

A **wordlist** supplies candidate seeds. A rule transforms a seed; an SSID profile combines transformation families. Pwnabase can use the network name as a seed or apply the profile to each entry in a wordlist. A larger candidate space can cost much more time even if memory stays bounded.

Hashcat performs the candidate verification. Pwnabase builds its command in [`recover`](../../pwnabase/tools.py), including:

```python
command = [options.hashcat, '-m', '22000', '-a', '0', '-D', options.device_types,
           '-w', '1', '--quiet', '--status', '--status-json']
```

This excerpt omits later arguments. Mode `22000` selects supported WPA verification; attack mode `0` uses candidate input; `-D` chooses device types. OpenCL provides a compute interface to available CPU or GPU devices. A detected GPU still needs a working backend and kernel, which the self-check exercises.

**Exercise:** Estimate the light profile without starting recovery:

```bash
python3 recover.py --ssid-rules light --estimate-only
```

The estimate samples the beginning of the configured wordlist and may not represent the whole list. Compare it with the full profile using `python3 recover.py --ssid-rules --estimate-only`; neither command processes captures. See [SSID-derived experiments](../../README.md#ssid-derived-experiments) for constraints and workload details.

## 6. Integrity, secrets, and reliable results

Pwnabase fingerprints input content with SHA-256. In [`fingerprint`](../../pwnabase/storage.py), it reads the file in blocks:

```python
digest = hashlib.sha256()
with path.open('rb') as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
return digest.hexdigest()
```

The fingerprint helps identify content and associate outcomes with their source. It is not encryption, and a matching digest alone does not establish who created a file. Snapshots and fingerprints help make attempts reproducible; result files retain provenance.

Recovered passwords are sensitive. The workflow uses restrictive permissions, avoids printing passwords in normal output, and disables Hashcat's potfile and logfile for recovery. Successful result JSON still contains recovered passwords, so it must be protected. The local viewer displays them and is intended for local use. See [`workflow.py`](../../pwnabase/workflow.py), [`tools.py`](../../pwnabase/tools.py), and [viewer behavior](../../frontend/README.md).

Atomic JSON replacement helps avoid leaving a partially written result after interruption. A lock prevents concurrent batches sharing an output directory. Transformed-wordlist attempts save confirmed checkpoints; after interruption, an unfinished candidate batch may be replayed. Other unfinished attempts restart from their beginning.

**Exercise:** Inspect saved transformed-wordlist checkpoints without starting a batch:

```bash
python3 recover.py --status
```

The output reports saved progress, not necessarily work currently in flight. If another output directory was used for the batch, supply the same `--output` path. Review [`atomic_json`](../../pwnabase/storage.py) to follow the temporary file, flush, replacement, and directory sync.

## Continue studying

Use [`./scripts/check`](../checks.md) to run the repository's checks, including synthetic tests. The [architecture guide](../architecture.md) explains ownership of the recovery modules, and the [README](../../README.md) documents real batch options and limitations. Deeper radio and Pwnagotchi study can be developed separately; this guide stays centered on Pwnabase's current offline workflow.

# Architecture

## Crate graph

```
ello-common ── types, config, paths (no deps on other ello crates)
     ▲
ello-engine ── scanning: sigdb, filetype, heuristics, ole, archive,
     ▲          scanner, update   (depends on ello-common)
     │
ello-quarantine ── encrypted vault (depends on ello-common)
     ▲
     ├── ello-cli      (ello)          engine + quarantine + common
     ├── ello-service  (ello-service)  engine + quarantine + common
     └── ello-sigtool  (ello-sigtool)  engine (sigdb + update)
```

The engine is a pure library: it performs no I/O policy decisions and never
deletes or moves files. Remediation (quarantine/delete) lives in the CLI and
service so the engine stays easy to test and embed.

## Scanning pipeline (`ello_engine::scanner::Engine::scan_bytes`)

1. **SHA-256 hash lookup** against the signature database → `Known` verdict.
2. **File-type detection** by content (`filetype::detect`), not extension.
3. **Pattern rules** applicable to that type, via an Aho-Corasick anchor
   prefilter (`sigdb`), each with wildcard/case/UTF-16 verification.
4. **Heuristics** (`heuristics`): weighted string/behaviour indicators, filename
   masquerade checks, PDF structure, and — for OLE documents — decompressed VBA
   macro source (`ole`). Scores are compared with sensitivity thresholds.
5. **Recursion** into ZIP-family containers (`archive`) with depth, per-entry,
   total-output, and compression-ratio limits; nested detections carry an
   `inner_path`.

A single object yields a `ScanOutcome` with zero or more `Detection`s, each
tagged with a `Confidence` (`Suspicious` < `Malicious` < `Known`) that drives
whether automated remediation acts.

## Trust model for updates

The engine only trusts signatures it can cryptographically verify:

* `ello-sigtool keygen` produces an Ed25519 keypair. The private key stays with
  the signature operator; the public key is distributed to endpoints.
* `ello-sigtool sign` produces a detached signature over the exact `.ellodb`
  bytes.
* `ello update trust` installs a public key under the data dir's `keys/`.
* `ello update apply` (`update::accept_update`) verifies the signature against
  every trusted key and requires the new `@version` to be strictly greater than
  the installed one, defeating tampering and rollback/downgrade attacks.

## Quarantine

Files are encrypted with ChaCha20-Poly1305 under a per-vault random key
(`vault.key`, owner-only where the OS supports it) and indexed in `index.json`
with original path, threat name, SHA-256, size and timestamp. Encryption makes
quarantined files inert (non-executable, not re-detected) while fully
restorable. This guards against accidental execution and casual inspection; it
is not a defence against an attacker with administrative read access to the
vault.

## Real-time protection

`ello-service` watches configured folders via the `notify` crate. A per-path
debouncer coalesces the burst of create/modify events an editor or installer
produces, scanning a file only after it has been quiet for the debounce window,
which avoids reading half-written files and redundant work. Detections are
remediated per the configured action. On Windows the process integrates with
the Service Control Manager; elsewhere it runs in the foreground under an init
supervisor.

## Known limitations

* **No kernel driver.** On-access *blocking* before a write completes needs a
  signed file-system mini-filter. Ello scans just after a change is observed.
* **No anti-tampering.** A privileged attacker can stop the service or delete
  the vault; a protected-process/ELAM posture requires Microsoft signing.
* **Seed signatures only.** Operational coverage depends on a maintained,
  signed signature feed and imported public hash intelligence.

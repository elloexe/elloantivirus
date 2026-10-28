# Ello Antivirus

A malware scanner for Windows, written in Rust. Ello pairs a signature engine
(exact hashes plus byte/string pattern rules) with score-based heuristics for
scripts, Office macros, PDFs and disguised files, and adds encrypted
quarantine, real-time folder protection, and cryptographically signed signature
updates.

> **Scope and honesty.** Ello is a complete, working *user-mode* antivirus. It
> does **not** include a kernel-mode mini-filter driver (which Microsoft
> requires to be WHQL-signed through the Hardware Dev Center and which 64-bit
> Windows will not load unsigned), protected-process anti-tampering, or a hosted
> cloud-reputation backend. It also ships only a tiny seed signature set — real
> detection coverage comes from an operated, continuously updated signature feed
> (see **Updates**). Everything here is the engine and tooling you build that
> product on top of.

## Components

| Crate | Binary | Purpose |
|-------|--------|---------|
| `ello-engine` | — | Scanning engine: hashes, pattern rules, heuristics, OLE/VBA macro extraction, bounded archive recursion, signed-update verification |
| `ello-common` | — | Shared verdict types, TOML configuration, data-dir layout |
| `ello-quarantine` | — | Encrypted (ChaCha20-Poly1305) quarantine vault |
| `ello-cli` | `ello` | Command-line scanner and manager |
| `ello-service` | `ello-service` | Real-time folder-protection service |
| `ello-sigtool` | `ello-sigtool` | Signature authoring, signing, and hash-feed import (vendor side) |

## Building

```sh
cargo build --release                                  # host build
cargo build --release --target x86_64-pc-windows-gnu   # Windows cross-build
cargo test                                             # run the test suite
```

The Windows cross-build needs the `x86_64-pc-windows-gnu` Rust target and the
MinGW-w64 toolchain (`x86_64-w64-mingw32-gcc`); see `.cargo/config.toml`.

## Using the scanner

```sh
ello scan C:\Users\me\Downloads          # scan a path (recursive)
ello quick                               # processes + autoruns + hot folders
ello full                                # all fixed drives
ello scan file.bin --json                # machine-readable output
ello scan x --action report|quarantine|delete
ello scan x --sensitivity off|low|normal|high

ello quarantine list
ello quarantine restore <id> [--to <path>]
ello quarantine remove <id>
ello quarantine clear

ello status
```

Exit codes: `0` clean, `1` threats found, `2` error.

## Real-time protection

```sh
ello-service run                 # foreground (supervise with systemd, etc.)

# Windows (run as Administrator):
ello-service install
ello-service start
ello-service stop
ello-service uninstall
```

Watched folders, the on-detection action, and the debounce window come from
`config.toml` (see `config.example.toml`).

## Updates

Signatures are distributed as a plain-text `.ellodb` file with a detached
Ed25519 signature. The engine installs an update only if the signature matches
a trusted key **and** the version is strictly newer (anti-rollback).

Vendor side (keep the private key offline):

```sh
ello-sigtool keygen --out signing.key                        # one-time
ello-sigtool import bazaar.csv --out latest.ellodb --version 2026102901
ello-sigtool sign latest.ellodb --key signing.key            # -> latest.ellodb.sig
```

Endpoint side:

```sh
ello update trust --file signing.pub --name vendor           # one-time
ello update apply --file latest.ellodb --sig latest.ellodb.sig
```

## Signature format

```text
@version 2026102801
H <sha256-hex> <ThreatName>
R <target> <min-matches> <ThreatName> <pattern> [<pattern> ...]
```

`target` ∈ `any|pe|script|ole|pdf|zip`. A pattern is a hex string with `??`
wildcards (`4d5a??00`), an ASCII literal (`"text"`), or a UTF-16LE literal
(`w"text"`); each literal run must be at least 4 bytes. A rule fires when at
least `min-matches` of its patterns are present. See `signatures/base.ellodb`
for examples.

## How detection works

1. **Exact hash** — SHA-256 against the database (highest confidence).
2. **Pattern rules** — multi-pattern Aho-Corasick prefilter, then verification,
   scoped by file type.
3. **Heuristics** — weighted indicators (download-and-run, AMSI/ETW tampering,
   Defender tampering, ransomware commands, obfuscation metrics, filename
   masquerading, PDF auto-actions, decompressed VBA macro source) summed against
   sensitivity thresholds.

Archives (ZIP/OOXML/JAR) are inspected recursively under depth, per-entry,
total-output and compression-ratio limits so an archive bomb cannot exhaust
resources.

## Testing against EICAR

Ello detects the standard [EICAR test file](https://www.eicar.org/) out of the
box, so you can verify scanning, quarantine and real-time protection without a
live sample.

## License

Proprietary. All rights reserved.

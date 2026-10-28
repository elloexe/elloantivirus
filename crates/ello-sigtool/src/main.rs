//! `ello-sigtool` — authoring and signing Ello Antivirus signature databases.
//!
//! This is the vendor-side counterpart to the engine's update verification:
//! it generates the Ed25519 signing keypair, signs a `.ellodb` file so the
//! scanner will accept it, and converts public malware hash feeds into
//! signature records.

mod importer;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ello_engine::sigdb::SignatureDb;
use ello_engine::update;

#[derive(Parser)]
#[command(name = "ello-sigtool", version, about = "Author and sign Ello Antivirus signatures")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 signing keypair.
    Keygen {
        /// Output path for the private key (hex). Public key is written beside it as `.pub`.
        #[arg(long, default_value = "ello-signing.key")]
        out: PathBuf,
    },
    /// Sign a `.ellodb` file, producing a detached `.sig`.
    Sign {
        /// The signature database to sign.
        file: PathBuf,
        /// Private signing key (hex), from `keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Output signature path (default: `<file>.sig`).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a `.ellodb` against a detached `.sig` and a public key.
    Verify {
        file: PathBuf,
        #[arg(long)]
        sig: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Import a public hash feed into `.ellodb` `H` records.
    Import {
        /// Input feed (plain hashes or CSV). `-` reads stdin.
        input: PathBuf,
        /// Output `.ellodb` file. `-` writes stdout.
        #[arg(long, default_value = "-")]
        out: PathBuf,
        /// Threat-name prefix for imported records.
        #[arg(long, default_value = "Imported")]
        prefix: String,
        /// Fallback name when a row has no label.
        #[arg(long, default_value = "Malware")]
        default_name: String,
        /// Database version stamp to write as `@version`.
        #[arg(long)]
        version: Option<u64>,
    },
    /// Validate a `.ellodb` file and print a summary.
    Lint { file: PathBuf },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn read_hex_key(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if raw.len() == 32 || raw.len() == 64 && raw.iter().all(|b| !b.is_ascii_hexdigit()) {
        return Ok(raw);
    }
    let text: String = raw.iter().filter(|b| !b.is_ascii_whitespace()).map(|&b| b as char).collect();
    hex::decode(&text).context("key file is not valid hex")
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { out } => {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let vk = sk.verifying_key();
            write_private(&out, hex::encode(sk.to_bytes()).as_bytes())?;
            let pub_path = out.with_extension("pub");
            std::fs::write(&pub_path, hex::encode(vk.to_bytes()))?;
            println!("Private key: {}", out.display());
            println!("Public key:  {}", pub_path.display());
            println!("\nInstall the public key on protected endpoints with:");
            println!("  ello update trust --file {}", pub_path.display());
            println!("Keep the private key offline and secret.");
        }
        Command::Sign { file, key, out } => {
            let content = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            // Fail fast if the content isn't a valid database.
            SignatureDb::parse(&String::from_utf8_lossy(&content)).context("file is not a valid .ellodb")?;
            let key_bytes = read_hex_key(&key)?;
            let arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
            let sk = SigningKey::from_bytes(&arr);
            let sig = sk.sign(&content);
            let out = out.unwrap_or_else(|| append_ext(&file, "sig"));
            std::fs::write(&out, hex::encode(sig.to_bytes()))?;
            println!("Signed {} -> {}", file.display(), out.display());
        }
        Command::Verify { file, sig, pubkey } => {
            let content = std::fs::read(&file)?;
            let sig_bytes = decode_hexish(&std::fs::read(&sig)?)?;
            let key_bytes = decode_hexish(&std::fs::read(&pubkey)?)?;
            let vk = VerifyingKey::from_bytes(&key_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?)
                .context("invalid public key")?;
            match update::verify(&content, &sig_bytes, &[vk]) {
                Ok(()) => println!("OK: signature is valid"),
                Err(e) => bail!("verification failed: {e}"),
            }
        }
        Command::Import { input, out, prefix, default_name, version } => {
            let text = read_input(&input)?;
            let (sigs, skipped) = importer::import_feed(&text, &default_name, &prefix);
            let mut body = String::new();
            if let Some(v) = version {
                body.push_str(&format!("@version {v}\n"));
            }
            body.push_str(&importer::to_ellodb(&sigs));
            // Round-trip through the parser to guarantee validity.
            SignatureDb::parse(&body).context("generated database failed validation")?;
            write_output(&out, body.as_bytes())?;
            eprintln!("Imported {} signatures ({} lines skipped)", sigs.len(), skipped);
        }
        Command::Lint { file } => {
            let text = std::fs::read_to_string(&file)?;
            let db = SignatureDb::parse(&text).context("invalid database")?;
            println!("OK: version {}, {} hashes, {} rules", db.version(), db.hash_count(), db.rule_count());
        }
    }
    Ok(())
}

fn decode_hexish(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() == 64 || raw.len() == 32 {
        if raw.iter().any(|b| !b.is_ascii_hexdigit() && !b.is_ascii_whitespace()) {
            return Ok(raw.to_vec());
        }
    }
    let text: String = raw.iter().filter(|b| !b.is_ascii_whitespace()).map(|&b| b as char).collect();
    hex::decode(&text).context("expected hex-encoded bytes")
}

fn read_input(path: &Path) -> Result<String> {
    if path.as_os_str() == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    }
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.as_os_str() == "-" {
        use std::io::Write;
        std::io::stdout().write_all(bytes)?;
        Ok(())
    } else {
        std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
    }
}

fn append_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_ext_adds_suffix() {
        assert_eq!(append_ext(Path::new("a/b.ellodb"), "sig"), PathBuf::from("a/b.ellodb.sig"));
    }
}

//! `openmoat audit checkpoint` and `openmoat audit verify --checkpoint` (ADR-110).

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::{Checkpoint, CheckpointCheck, Store, VerifierKey};
use serde::Serialize;

use crate::audit_signing;
use crate::cli::{CheckpointArgs, Format};
use crate::exit::Code;
use crate::home::Home;
use crate::render::{self, Deferred};

#[derive(Serialize)]
struct Signed<'a> {
    path: String,
    size: u64,
    root: String,
    public_key: String,
    fingerprint: String,
    note: &'a str,
}

/// Person-only, as an anchor is: a checkpoint is the person's statement of
/// what the log held, made only over a chain that verifies.
pub fn run(args: &CheckpointArgs) -> Result<Code> {
    crate::terminal::refuse_agent("openmoat audit checkpoint")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat audit checkpoint` must be run by a person in a terminal, not from a hook \
             or script"
        );
    }
    let home = Home::locate()?;
    let store = home.open_audit()?;
    refuse_broken(&store, "sign a checkpoint of")?;
    let mut out = Deferred::default();
    let key = if args.new_key {
        // A new key re-pins what verifiers trust: the gate asks (ADR-117).
        let pass = crate::gate::pass(&home, "openmoat audit checkpoint --new-key")?;
        let (key, kept) = audit_signing::rotate(&home)?;
        pass.record(
            &home,
            &format!(
                "audit signing key replaced by {}",
                key.verifier().fingerprint()
            ),
            &[],
        );
        if let Some(kept) = kept {
            writeln!(
                out,
                "✔ new signing key; the old one is kept as {}: checkpoints it signed still \
                 verify with its public key",
                kept.display()
            )?;
        }
        key
    } else {
        let (key, made) = audit_signing::ensure(&home)?;
        if made {
            writeln!(
                out,
                "✔ made the audit signing key {}",
                audit_signing::path(&home).display()
            )?;
        }
        key
    };
    let written = audit_signing::sign_now(&home, &store, &key)?;
    let verifier = key.verifier();
    if args.format == Format::Json {
        return render::json(&Signed {
            path: written.path.display().to_string(),
            size: written.checkpoint.size,
            root: written.checkpoint.root_hex(),
            public_key: verifier.to_string(),
            fingerprint: verifier.fingerprint(),
            note: &written.note,
        })
        .map(|()| Code::Ok);
    }
    writeln!(
        out,
        "✔ signed a checkpoint of {} chained events: {}",
        written.checkpoint.size,
        written.path.display()
    )?;
    write!(out, "\n{}\n", written.note)?;
    writeln!(out, "public key  {verifier}")?;
    writeln!(out, "            {}", verifier.fingerprint())?;
    writeln!(
        out,
        "nothing was sent anywhere: keep a copy of the checkpoint and the public key off this \
         machine; check an export later with\n  openmoat audit verify <export> --checkpoint <file> \
         --pubkey <public key>"
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

/// An error when `store`'s chain breaks: nothing is signed over it.
fn refuse_broken(store: &Store, what: &str) -> Result<()> {
    if let Some(broken) = store.verify_chain()?.broken {
        bail!(
            "refusing to {what} a broken log: the hash chain breaks at event {}: {}; keep the \
             file as evidence",
            broken.id,
            broken.kind.describe()
        );
    }
    Ok(())
}

/// The checkpoint in `file`, once `pubkey` (a key, or a file holding one) is
/// shown to have signed it.
pub fn open(file: &Path, pubkey: &str) -> Result<Checkpoint> {
    let key = match VerifierKey::parse(pubkey) {
        Ok(key) => key,
        Err(direct) => {
            let text = std::fs::read_to_string(pubkey).map_err(|_| direct)?;
            VerifierKey::parse(&text).with_context(|| format!("reading {pubkey}"))?
        }
    };
    let note =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    Checkpoint::open(&note, &key).with_context(|| format!("checking {}", file.display()))
}

#[derive(Serialize)]
struct Local {
    chain_broken: Option<openmoat_audit::ChainBreak>,
    checkpoint: CheckpointCheck,
}

/// `openmoat audit verify --checkpoint` without an export: this machine's
/// log, its chain first. Exit 0 when both hold, else 64.
pub fn verify_local(file: &Path, pubkey: &str, format: Format) -> Result<Code> {
    let checkpoint = open(file, pubkey)?;
    let home = Home::locate()?;
    let store = home.open_audit()?;
    let chain = store.verify_chain()?;
    let check = store.check_checkpoint(&checkpoint)?;
    let code = if chain.broken.is_none() && check.holds() {
        Code::Ok
    } else {
        Code::Usage
    };
    if format == Format::Json {
        render::json(&Local {
            chain_broken: chain.broken,
            checkpoint: check,
        })?;
        return Ok(code);
    }
    let mut out = Deferred::default();
    if let Some(broken) = &chain.broken {
        writeln!(
            out,
            "✗ the hash chain breaks at event {}: {}",
            broken.id,
            broken.kind.describe()
        )?;
    }
    line(&mut out, check)?;
    out.finish()?;
    Ok(code)
}

/// The line `openmoat audit verify` prints for a checkpoint check.
pub fn line(out: &mut impl std::io::Write, check: CheckpointCheck) -> Result<()> {
    let mark = if check.holds() { "✔" } else { "✗" };
    writeln!(
        out,
        "{mark} checkpoint (signature verified): {}",
        check.describe()
    )?;
    Ok(())
}

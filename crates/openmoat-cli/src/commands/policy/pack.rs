//! `moat policy trust-key`, `moat policy install` and `moat policy remove`
//! (ADR-031): signed policy packs.
//!
//! Person-only, like `moat trust`: each widens what the policy trusts, so each
//! needs a terminal and an intact lock, and the default policy denies `moat
//! policy` to agents. Each pins what it wrote and keeps every other pin.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::cli::{InstallArgs, RemoveArgs, TrustKeyArgs};
use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity::{self, HookPins, sha256_hex};
use crate::packs::{self, Installed, Packs};
use crate::render::Deferred;
use crate::signing;

/// The checks every pack command makes before it writes; the state directory.
fn person(command: &str, doing: &str) -> Result<Home> {
    crate::terminal::refuse_agent(command)?;
    if !crate::terminal::interactive() {
        bail!("`{command}` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    integrity::refuse_drift(&home, doing)?;
    Ok(home)
}

/// Re-pin, keeping every pin, with the signing files as they are now.
fn repin(home: &Home) -> Result<usize> {
    let files = integrity::signing_files(home);
    let lock = integrity::repin_with(
        home,
        &crate::install::hook_binary()?,
        HookPins::Keep,
        &files,
        &[],
    )?;
    Ok(lock.entries.len())
}

pub fn trust_key(args: &TrustKeyArgs) -> Result<Code> {
    let home = person("openmoat policy trust-key", "trust a signing key")?;
    let program = signing::require(&home)?;
    let key =
        fs::read_to_string(&args.key).with_context(|| format!("reading {}", args.key.display()))?;
    let line = signing::signer_line(&args.name, &key)?;
    let fingerprint = signing::fingerprint(&program, &args.key)?;
    let path = home.signers_path();
    // Only a pinned file is the person's; anything else there is replaced.
    let mut text = match signing::trusted_signers(&home) {
        Some(current) => fs::read_to_string(&current)
            .with_context(|| format!("reading {}", current.display()))?,
        None => String::new(),
    };
    let mut out = Deferred::default();
    if text.lines().any(|l| l.trim() == line) {
        writeln!(out, "{} is already trusted as {}", fingerprint, args.name)?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&line);
    text.push('\n');
    write_private(&path, text.as_bytes())?;
    let pinned = repin(&home)?;
    writeln!(
        out,
        "✔ trusted {fingerprint} as {} to sign policy (namespace {})",
        args.name,
        signing::NAMESPACE
    )?;
    writeln!(out, "✔ lock re-pinned ({pinned} files)")?;
    out.finish()?;
    Ok(Code::Ok)
}

/// `<pack>.sig` beside the pack.
fn default_sig(pack: &Path) -> PathBuf {
    let mut sig = pack.as_os_str().to_owned();
    sig.push(".sig");
    PathBuf::from(sig)
}

pub fn install(args: &InstallArgs) -> Result<Code> {
    let home = person("openmoat policy install", "install a policy pack")?;
    let program = signing::require(&home)?;
    let name = match &args.name {
        Some(name) => name.clone(),
        None => args
            .pack
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default(),
    };
    packs::check_name(&name)?;
    let signers = signing::trusted_signers(&home).context(
        "no key is trusted to sign policy yet; add your team's with `openmoat policy trust-key`",
    )?;
    let text = fs::read_to_string(&args.pack)
        .with_context(|| format!("reading {}", args.pack.display()))?;
    let sig = args.sig.clone().unwrap_or_else(|| default_sig(&args.pack));
    let signature =
        fs::read(&sig).with_context(|| format!("reading signature {}", sig.display()))?;
    // The bytes that verify are the bytes installed: the copy below is made
    // from this same text, and the signature from these same bytes.
    let staged = home.packs_dir().join(format!(".{name}.staged.sig"));
    write_private(&staged, &signature)?;
    let signer = signing::verify(&program, &signers, text.as_bytes(), &staged);
    let _ = fs::remove_file(&staged);
    let Some(signer) = signer? else {
        bail!(
            "refusing {}: its signature {} does not verify against any key `openmoat policy \
             trust-key` trusted (namespace {})",
            args.pack.display(),
            sig.display(),
            signing::NAMESPACE
        );
    };
    let pack =
        packs::parse(&text).with_context(|| format!("policy pack {}", args.pack.display()))?;
    // The merged policy must still lint before anything is written, with the
    // pack this one replaces taken out.
    let mut policy = home.load_policy()?;
    let own = format!("{}{name}:", packs::PACK_RULE_PREFIX);
    for groups in [&mut policy.deny, &mut policy.repo_ask, &mut policy.allow] {
        groups.retain(|g| !g.id.starts_with(&own));
    }
    packs::apply(&mut policy, &name, &pack)?;

    write_private(&packs::pack_path(&home, &name), text.as_bytes())?;
    write_private(&packs::sig_path(&home, &name), &signature)?;
    let mut installed = Packs::load(&home.packs_path())?;
    let replaced = installed.packs.insert(
        name.clone(),
        Installed {
            sha256: sha256_hex(text.as_bytes()),
            signer: signer.clone(),
            at_ms: crate::time::now_ms(),
        },
    );
    installed.save(&home.packs_path())?;
    let pinned = repin(&home)?;

    let mut out = Deferred::default();
    for (verb, groups) in [
        ("deny", &pack.deny),
        ("ask", &pack.ask),
        ("allow", &pack.allow),
    ] {
        for group in groups {
            writeln!(
                out,
                "  {verb} {}{name}:{}",
                packs::PACK_RULE_PREFIX,
                group.id
            )?;
        }
    }
    let how = if replaced.is_some() {
        "replaced"
    } else {
        "installed"
    };
    writeln!(
        out,
        "✔ {how} policy pack `{name}` signed by {signer}: {} deny, {} ask, {} allow rule(s)",
        pack.deny.len(),
        pack.ask.len(),
        pack.allow.len()
    )?;
    writeln!(out, "✔ lock re-pinned ({pinned} files)")?;
    out.finish()?;
    Ok(Code::Ok)
}

pub fn remove(args: &RemoveArgs) -> Result<Code> {
    let home = person("openmoat policy remove", "remove a policy pack")?;
    packs::check_name(&args.name)?;
    let mut installed = Packs::load(&home.packs_path())?;
    if installed.packs.remove(&args.name).is_none() {
        bail!("no policy pack `{}` is installed", args.name);
    }
    let files = [
        packs::pack_path(&home, &args.name),
        packs::sig_path(&home, &args.name),
    ];
    installed.save(&home.packs_path())?;
    for file in &files {
        let _ = fs::remove_file(file);
    }
    integrity::unpin(&home, &files, &[home.packs_path()])?;
    let mut out = Deferred::default();
    writeln!(
        out,
        "✔ removed policy pack `{}`; its rules no longer apply",
        args.name
    )?;
    out.finish()?;
    Ok(Code::Ok)
}

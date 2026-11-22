//! `openmoat doctor`'s rows for the audit signing key and the newest signed
//! checkpoint (ADR-110).

use openmoat_audit::Checkpoint;

use super::Area;
use super::human::Place;
use super::rows::Report;
use crate::audit_signing;
use crate::home::Home;

/// The public key, to compare with a copy kept elsewhere, and whether the log
/// still holds what the newest checkpoint states. No key is a note, not a
/// problem: a log from before checkpoints records as it did.
pub(super) fn lines(report: &mut Report, home: &Home) {
    let key = match audit_signing::read(home) {
        Ok(Some(key)) => key,
        Ok(None) => {
            report.note_at(
                "audit signing    no key yet: `openmoat audit checkpoint` (or `openmoat init`) \
                 makes one, and checkpoints others can check",
                Place::OpenMoat,
            );
            return;
        }
        Err(e) => {
            report.line(Area::Audit, false, format!("audit signing    {e:#}"));
            return;
        }
    };
    let verifier = key.verifier();
    report.note_at(
        &format!(
            "audit signing    public key {verifier} ({}); give it to whoever checks your \
             checkpoints",
            verifier.fingerprint()
        ),
        Place::OpenMoat,
    );
    let Some((path, note)) = audit_signing::latest(home, verifier) else {
        return;
    };
    let shown = path.display();
    let check = Checkpoint::open(&note, verifier)
        .map_err(anyhow::Error::from)
        .and_then(|cp| {
            let store = home.open_audit()?;
            Ok(store.check_checkpoint(&cp)?)
        });
    match check {
        Ok(check) if check.holds() => report.note_at(
            &format!("audit checkpoint {shown}: {}", check.describe()),
            Place::OpenMoat,
        ),
        Ok(check) => report.line(
            Area::Audit,
            false,
            format!(
                "audit checkpoint {shown}: {}; keep the log as evidence",
                check.describe()
            ),
        ),
        Err(e) => report.line(
            Area::Audit,
            false,
            format!("audit checkpoint {shown}: {e:#}"),
        ),
    }
}

use super::*;

/// RFC 6238 Appendix B's SHA-1 secret: the ASCII of `12345678901234567890`.
const RFC_SECRET: &[u8] = b"12345678901234567890";

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    // Not `.moat`: a sandbox the tests may run in refuses writes to one.
    let home = Home::at(dir.path().join("state"));
    std::fs::create_dir_all(home.root()).unwrap();
    (dir, home)
}

fn typed(code: &str) -> impl FnOnce() -> Result<Zeroizing<String>> {
    let code = code.to_owned();
    move || Ok(Zeroizing::new(code))
}

#[test]
fn hotp_matches_rfc_4226_appendix_d() {
    let expected = [
        755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871, 520_489,
    ];
    for (counter, want) in (0u64..).zip(expected) {
        assert_eq!(
            totp::hotp(RFC_SECRET, counter, 6),
            want,
            "counter {counter}"
        );
    }
}

#[test]
fn totp_matches_rfc_6238_appendix_b_for_sha1() {
    for (time, want) in [
        (59u64, 94_287_082),
        (1_111_111_109, 7_081_804),
        (1_111_111_111, 14_050_471),
        (1_234_567_890, 89_005_924),
        (2_000_000_000, 69_279_037),
        (20_000_000_000, 65_353_130),
    ] {
        assert_eq!(
            totp::hotp(RFC_SECRET, totp::step(time), 8),
            want,
            "time {time}"
        );
    }
    // Six digits are the last six of the eight, zero-padded.
    assert_eq!(totp::code(RFC_SECRET, totp::step(59)), "287082");
    assert_eq!(totp::code(RFC_SECRET, totp::step(1_111_111_109)), "081804");
}

#[test]
fn a_code_is_taken_within_one_step_and_once() {
    let now = 1_111_111_111;
    let step = totp::step(now);
    let current = totp::code(RFC_SECRET, step);
    assert_eq!(totp::check(RFC_SECRET, &current, now, 0), Ok(step));
    // The step before and after still count; two away does not.
    let before = totp::code(RFC_SECRET, step - 1);
    assert_eq!(totp::check(RFC_SECRET, &before, now, 0), Ok(step - 1));
    let after = totp::code(RFC_SECRET, step + 1);
    assert_eq!(totp::check(RFC_SECRET, &after, now, 0), Ok(step + 1));
    let far = totp::code(RFC_SECRET, step - 2);
    assert_eq!(
        totp::check(RFC_SECRET, &far, now, 0),
        Err(totp::Refusal::Wrong)
    );
    // Taken once: the same step again, or an earlier one after it, is replayed.
    assert_eq!(
        totp::check(RFC_SECRET, &current, now, step),
        Err(totp::Refusal::Replayed)
    );
    assert_eq!(
        totp::check(RFC_SECRET, &before, now, step),
        Err(totp::Refusal::Replayed)
    );
}

#[test]
fn a_missing_or_malformed_code_is_refused() {
    let now = 59;
    for (input, want) in [
        ("", totp::Refusal::Missing),
        ("  \n", totp::Refusal::Missing),
        ("28708", totp::Refusal::Malformed),
        ("2870822", totp::Refusal::Malformed),
        ("28708a", totp::Refusal::Malformed),
        ("000000", totp::Refusal::Wrong),
    ] {
        assert_eq!(
            totp::check(RFC_SECRET, input, now, 0),
            Err(want),
            "{input:?}"
        );
    }
    assert_eq!(totp::check(RFC_SECRET, " 287082\n", now, 0), Ok(1));
}

#[test]
fn base32_round_trips_and_matches_rfc_4648() {
    assert_eq!(secret::base32(b"foobar").as_str(), "MZXW6YTBOI");
    assert_eq!(
        secret::base32(RFC_SECRET).as_str(),
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    );
    let raw = secret::generate().unwrap();
    assert_eq!(raw.len(), secret::LEN);
    let text = secret::base32(&raw);
    assert_eq!(secret::unbase32(&text).unwrap().as_slice(), raw.as_slice());
    // As apps show it: grouped, in lower case, padded.
    let grouped = secret::grouped(&raw).to_ascii_lowercase();
    assert_eq!(
        secret::unbase32(&format!("{grouped}===="))
            .unwrap()
            .as_slice(),
        raw.as_slice()
    );
    assert!(secret::unbase32("not base32!").is_none());
}

#[test]
fn the_uri_names_the_parameters_the_codes_use() {
    let uri = secret::uri(RFC_SECRET);
    assert!(
        uri.starts_with("otpauth://totp/OpenMoat:")
            && uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            && uri.contains("issuer=OpenMoat")
            && uri.contains("algorithm=SHA1")
            && uri.contains("digits=6")
            && uri.contains("period=30"),
        "{}",
        uri.as_str()
    );
}

#[test]
fn the_secret_file_parses_only_in_its_own_form() {
    let file = secret::encode_file(RFC_SECRET);
    assert_eq!(secret::parse(&file).unwrap().as_slice(), RFC_SECRET);
    assert!(secret::parse("GEZDGNBVGY3TQOJQ\n").is_err());
    assert!(secret::parse("openmoat-gate-totp-v1\n").is_err());
    // Shorter than 128 bits.
    assert!(secret::parse("openmoat-gate-totp-v1\nMZXW6YTBOI\n").is_err());
}

#[test]
fn the_secret_is_private_and_named_under_the_audit_key() {
    // `kernel-self` denies `audit.key*` to agents: the secret and its
    // temporary file (`tests/conformance/attacks.yaml`, T9-read-the-gate-secret).
    assert!(KEY_FILE.starts_with(crate::audit_key::KEY_FILE));
    let (_dir, home) = home();
    assert!(!enrolled(&home));
    write_secret(&home);
    assert!(enrolled(&home));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path(&home)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
        // Others may read it: refused, and the error never holds the secret.
        std::fs::set_permissions(path(&home), std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = format!("{:#}", secret::read(&path(&home)).unwrap_err());
        assert!(!error.contains("GEZDGNBV"), "{error}");
    }
}

fn write_secret(home: &Home) {
    assert!(
        crate::home::write_private_new(&path(home), secret::encode_file(RFC_SECRET).as_bytes())
            .unwrap()
    );
}

#[test]
fn a_good_code_passes_once_and_its_replay_is_refused() {
    let (_dir, home) = home();
    write_secret(&home);
    let now = 1_234_567_890;
    let code = totp::code(RFC_SECRET, totp::step(now));
    let step = take(&home, "openmoat allow", RFC_SECRET, now, typed(&code)).unwrap();
    assert_eq!(step, totp::step(now));
    let error = take(&home, "openmoat allow", RFC_SECRET, now + 5, typed(&code)).unwrap_err();
    assert!(format!("{error}").contains("already used"), "{error}");
    // The next step's code is taken.
    let next = totp::code(RFC_SECRET, totp::step(now) + 1);
    take(&home, "openmoat allow", RFC_SECRET, now + 30, typed(&next)).unwrap();
}

#[test]
fn a_wrong_or_missing_code_is_refused_and_counted() {
    let (_dir, home) = home();
    write_secret(&home);
    let now = 1_234_567_890;
    for code in ["000000", ""] {
        let error = take(&home, "openmoat trust", RFC_SECRET, now, typed(code)).unwrap_err();
        assert!(
            format!("{error}").contains("nothing was changed"),
            "{error}"
        );
    }
    let state = state::State::load(&state_path(&home)).unwrap();
    assert_eq!(state.failures.len(), 2);
    // A good code clears the count.
    let code = totp::code(RFC_SECRET, totp::step(now));
    take(&home, "openmoat trust", RFC_SECRET, now, typed(&code)).unwrap();
    let state = state::State::load(&state_path(&home)).unwrap();
    assert_eq!(state.failures, Vec::<i64>::new());
}

#[test]
fn wrong_codes_lock_the_gate_until_the_window_passes() {
    let (_dir, home) = home();
    write_secret(&home);
    let now = 1_234_567_890;
    for n in 0..MAX_FAILURES {
        let at = now + u64::try_from(n).unwrap();
        take(&home, "openmoat edit", RFC_SECRET, at, typed("000000")).unwrap_err();
    }
    // Locked: even the right code is not asked for, let alone taken.
    let code = totp::code(RFC_SECRET, totp::step(now + 10));
    let error = take(&home, "openmoat edit", RFC_SECRET, now + 10, || {
        panic!("the code is asked for while the gate is locked")
    })
    .unwrap_err();
    assert!(format!("{error}").contains("wrong codes"), "{error}");
    // Once the first wrong code leaves the window, one more try is allowed.
    let later = now + u64::try_from(WINDOW_MS / 1000).unwrap() + 1;
    let code_later = totp::code(RFC_SECRET, totp::step(later));
    assert_ne!(code, code_later);
    take(
        &home,
        "openmoat edit",
        RFC_SECRET,
        later,
        typed(&code_later),
    )
    .unwrap();
}

#[test]
fn the_lock_lasts_from_the_oldest_counted_failure() {
    let mut state = state::State::default();
    for t in [1_000, 2_000, 3_000, 4_000] {
        state.failed(t);
    }
    assert_eq!(state.locked_until(4_000), None);
    state.failed(5_000);
    assert_eq!(state.locked_until(5_000), Some(1_000 + WINDOW_MS));
    assert_eq!(state.locked_until(1_000 + WINDOW_MS), None);
}

#[test]
fn a_state_file_that_does_not_parse_is_refused() {
    let (_dir, home) = home();
    std::fs::write(state_path(&home), "{ not json").unwrap();
    assert!(state::State::load(&state_path(&home)).is_err());
}

#[test]
fn without_enrolment_a_loosening_passes_unasked() {
    let (_dir, home) = home();
    let pass = pass(&home, "openmoat allow").unwrap();
    assert_eq!(pass.factor(), Factor::NotEnrolled);
}

#[test]
fn enrolment_needs_a_code_of_the_new_secret_and_happens_once() {
    let (_dir, home) = home();
    let enrolment = Enrolment::new().unwrap();
    let error = enrolment.confirm(&home, "000000").unwrap_err();
    assert!(
        format!("{error:#}").contains("nothing was set up"),
        "{error:#}"
    );
    assert!(!enrolled(&home));
    let raw = secret::unbase32(&enrolment.text()).unwrap();
    let code = totp::code(&raw, totp::step(now_secs()));
    enrolment.confirm(&home, &code).unwrap();
    assert!(enrolled(&home));
    assert_eq!(
        secret::read(&path(&home)).unwrap().as_slice(),
        raw.as_slice()
    );
    // The code typed at setup is used: it cannot confirm a loosening after.
    let state = state::State::load(&state_path(&home)).unwrap();
    assert!(state.last_step + totp::SKEW >= totp::step(now_secs()) - 1);
    assert_eq!(
        totp::check(&raw, &code, now_secs(), state.last_step),
        Err(totp::Refusal::Replayed)
    );
    // A second enrolment over the first is refused.
    let again = Enrolment::new().unwrap();
    let raw = secret::unbase32(&again.text()).unwrap();
    let code = totp::code(&raw, totp::step(now_secs()) + 1);
    assert!(again.confirm(&home, &code).is_err());
    remove(&home).unwrap();
    assert!(!enrolled(&home));
    assert!(!state_path(&home).exists());
}

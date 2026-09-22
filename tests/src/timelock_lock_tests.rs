/// Integration tests for the timelock-lock contract.
///
/// The timelock-lock witness has three fields in declaration order:
///   1. `signature`      — [u8; 65]  secp256k1_sig     (fixed, 65 bytes)
///   2. `unlock_after_ms`— u64       uint64             (fixed, 8 bytes LE)
///   3. `extra`          — Vec<u8>   bytes              (variable, length-prefixed)
///
/// Wire format (length-prefix encoding, same as ckb-idl-derive):
///   [ sig: 65 bytes ][ unlock_after_ms: 8 bytes LE ][ len: 4 bytes LE ][ extra: len bytes ]
///
/// Args layout (33–65 bytes):
///   args[0..33]  — compressed secp256k1 pubkey (placeholder bytes in tests)
///   args[33..65] — blake2b-256 commitment of expected `extra` (optional)
///
/// Script logic tested:
///   - TimelockNotMet (12):   block timestamp < unlock_after_ms
///   - SignatureInvalid (11): signature is all zeros
///   - Encoding (4):          extra hash mismatch when commitment in args
///   - Success:               non-zero sig, timestamp passed, extra matches commitment
use ckb_idl_client::{DecodedValue, IdlClient, IdlDocument, WitnessField};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_hash::blake2b_256;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 10_000_000;

// ── IDL loading ──────────────────────────────────────────────────────────────

fn load_timelock_idl() -> IdlDocument {
    let idl_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/timelock-lock/idl.json"
    );
    let json = std::fs::read_to_string(idl_path)
        .expect("timelock-lock idl.json not found — run `make build` first");

    let raw: serde_json::Value = serde_json::from_str(&json).expect("idl.json is not valid JSON");

    let witness_fields: Vec<WitnessField> =
        serde_json::from_value(raw["witness"].clone()).expect("idl.json has no 'witness' array");

    IdlDocument {
        idl_version: "1".to_string(),
        name: "timelock-lock".to_string(),
        witness: witness_fields,
        description: None,
        script_version: None,
        signing: None,
    }
}

// ── Wire encoding ─────────────────────────────────────────────────────────────

/// Encode a full timelock-lock witness.
///
/// Wire layout:
///   [ signature: 65 bytes ][ unlock_after_ms: 8 bytes LE ]
///   [ extra_len: 4 bytes LE ][ extra: extra_len bytes ]
fn encode_timelock_witness(signature: &[u8; 65], unlock_after_ms: u64, extra: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(signature);
    buf.extend_from_slice(&unlock_after_ms.to_le_bytes());
    let extra_len = extra.len() as u32;
    buf.extend_from_slice(&extra_len.to_le_bytes());
    buf.extend_from_slice(extra);
    buf
}

// ── VM test helpers ───────────────────────────────────────────────────────────

/// A placeholder non-zero 65-byte signature (all 0x01).
/// The contract's placeholder check only rejects all-zeros.
const FAKE_SIG: [u8; 65] = [0x01u8; 65];

/// A dummy 33-byte pubkey stored in args[0..33].
const DUMMY_PUBKEY: [u8; 33] = [0x02u8; 33];

/// Build args for timelock-lock.
fn build_args(commitment: Option<[u8; 32]>) -> Bytes {
    let mut args = DUMMY_PUBKEY.to_vec();
    if let Some(c) = commitment {
        args.extend_from_slice(&c);
    }
    Bytes::from(args)
}

/// Deploy timelock-lock and create a locked cell linked to a header
/// with the given block timestamp.
fn setup_timelock_cell(args: Bytes, block_timestamp_ms: u64) -> (Context, OutPoint, Byte32) {
    let mut context = Context::default();

    let header = ckb_testtool::ckb_types::core::HeaderBuilder::default()
        .timestamp(block_timestamp_ms)
        .build();
    context.insert_header(header.clone());

    let lock_out_point = context.deploy_cell_by_name("timelock-lock");
    let lock_script = context
        .build_script(&lock_out_point, args)
        .expect("lock script");
    let locked_cell = context.create_cell(
        CellOutput::new_builder()
            .capacity(1_000u64)
            .lock(lock_script)
            .build(),
        Bytes::new(),
    );

    context.link_cell_with_block(locked_cell.clone(), header.hash(), 0);

    (context, locked_cell, header.hash())
}

fn build_always_success_output(context: &mut Context) -> Script {
    let op = context.deploy_cell(ALWAYS_SUCCESS.clone());
    context
        .build_script(&op, Bytes::new())
        .expect("always-success")
}

/// Build and run a spend transaction for the locked cell.
fn run_tx(
    context: &mut Context,
    locked_cell: OutPoint,
    header_dep: Byte32,
    wire: Vec<u8>,
) -> Result<u64, ckb_testtool::ckb_error::Error> {
    let output_lock = build_always_success_output(context);

    let input = CellInput::new_builder()
        .previous_output(locked_cell)
        .build();
    let output = CellOutput::new_builder()
        .capacity(1_000u64)
        .lock(output_lock)
        .build();

    let witness_args = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(wire)).pack())
        .build();

    let tx = TransactionBuilder::default()
        .header_dep(header_dep)
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .witness(witness_args.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    context.verify_tx(&tx, MAX_CYCLES)
}

// ─────────────────────────────────────────────────────────────────────────────
// PSCT structural validation tests (no VM)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_idl_has_three_fields() {
    let idl = load_timelock_idl();
    assert_eq!(idl.witness.len(), 3);
    assert_eq!(idl.witness[0].name, "signature");
    assert_eq!(idl.witness[1].name, "unlock_after_ms");
    assert_eq!(idl.witness[2].name, "extra");
}

#[test]
fn test_witness_validation_passes_full_witness() {
    let idl = load_timelock_idl();
    let sig = [0x04u8; 65];
    let ts: u64 = 1_700_000_000_000;
    let extra = b"merkle_proof_data";

    let wire = encode_timelock_witness(&sig, ts, extra);

    let client = IdlClient::new();
    let validated = client
        .validate_witness_bytes(&idl.witness, &wire)
        .expect("full witness should pass structural validation");

    assert_eq!(validated.len(), 3);
    assert_eq!(validated[0].name, "signature");
    assert_eq!(validated[0].type_, "secp256k1_sig");
    assert!(validated[0].required);
    assert_eq!(validated[0].value, DecodedValue::Bytes(sig.to_vec()));

    assert_eq!(validated[1].name, "unlock_after_ms");
    assert_eq!(validated[1].type_, "uint64");
    assert!(validated[1].required);
    assert_eq!(validated[1].value, DecodedValue::U64(ts));

    assert_eq!(validated[2].name, "extra");
    assert_eq!(validated[2].type_, "bytes");
    // The flat compatibility lock always encodes the length-prefixed extra
    // field; an empty payload represents the no-extra case.
    assert!(validated[2].required);
    assert_eq!(validated[2].value, DecodedValue::Bytes(extra.to_vec()));
}

#[test]
fn test_witness_validation_passes_empty_extra() {
    let idl = load_timelock_idl();
    let wire = encode_timelock_witness(&FAKE_SIG, 0, &[]);

    let client = IdlClient::new();
    let validated = client
        .validate_witness_bytes(&idl.witness, &wire)
        .expect("witness with empty extra should pass");
    assert_eq!(validated[2].value, DecodedValue::Bytes(vec![]));
}

#[test]
fn test_witness_validation_fails_missing_timestamp() {
    let idl = load_timelock_idl();
    let buf = vec![0x01u8; 65]; // only signature, no timestamp

    let client = IdlClient::new();
    let err = client
        .validate_witness_bytes(&idl.witness, &buf)
        .unwrap_err();
    assert!(
        matches!(err, ckb_idl_client::IdlError::FieldTooShort { ref field, .. } if field == "unlock_after_ms"),
        "expected FieldTooShort for unlock_after_ms, got {:?}",
        err
    );
}

#[test]
fn test_witness_validation_fails_truncated_timestamp() {
    let idl = load_timelock_idl();
    let mut buf = vec![0x01u8; 65];
    buf.extend_from_slice(&[0x00, 0x01, 0x02]); // only 3 of 8 timestamp bytes

    let client = IdlClient::new();
    let err = client
        .validate_witness_bytes(&idl.witness, &buf)
        .unwrap_err();
    assert!(
        matches!(err, ckb_idl_client::IdlError::FieldTooShort {
            ref field,
            expected: 8,
            got: 3,
        } if field == "unlock_after_ms"),
        "expected FieldTooShort {{ field: unlock_after_ms, expected: 8, got: 3 }}, got {:?}",
        err
    );
}

#[test]
fn test_witness_validation_fails_truncated_extra_prefix() {
    let idl = load_timelock_idl();
    let mut buf = vec![0x01u8; 65];
    buf.extend_from_slice(&1_000u64.to_le_bytes());
    buf.extend_from_slice(&[0x00, 0x01]); // only 2 of 4 prefix bytes

    let client = IdlClient::new();
    let err = client
        .validate_witness_bytes(&idl.witness, &buf)
        .unwrap_err();
    assert!(
        matches!(err, ckb_idl_client::IdlError::FieldTooShort {
            ref field,
            expected: 4,
            got: 2,
        } if field == "extra"),
        "expected FieldTooShort {{ field: extra, expected: 4, got: 2 }}, got {:?}",
        err
    );
}

#[test]
fn test_witness_validation_fails_trailing_bytes() {
    let idl = load_timelock_idl();
    let mut wire = encode_timelock_witness(&FAKE_SIG, 0, b"data");
    wire.extend_from_slice(b"extra"); // 5 trailing bytes

    let client = IdlClient::new();
    let err = client
        .validate_witness_bytes(&idl.witness, &wire)
        .unwrap_err();
    assert!(
        matches!(
            err,
            ckb_idl_client::IdlError::TrailingBytes { trailing: 5, .. }
        ),
        "expected TrailingBytes {{ trailing: 5 }}, got {:?}",
        err
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Full PSCT flow: validate then execute via CKB VM
// ─────────────────────────────────────────────────────────────────────────────

/// PSCT passes and VM accepts: unlock time has passed.
#[test]
fn test_psct_validate_then_execute_timelock_passes() {
    let idl = load_timelock_idl();

    let unlock_after_ms: u64 = 1_000_000;
    let block_ts: u64 = 2_000_000; // block time is after unlock time → allowed

    let wire = encode_timelock_witness(&FAKE_SIG, unlock_after_ms, &[]);

    let client = IdlClient::new();
    let validated = client
        .validate_witness_bytes(&idl.witness, &wire)
        .expect("witness should pass PSCT validation");

    println!("PSCT validation passed for timelock-lock. Decoded fields:");
    for f in &validated {
        println!("  {} ({}): {:?}", f.name, f.type_, f.value);
    }

    let args = build_args(None);
    let (mut ctx, locked_cell, header_dep) = setup_timelock_cell(args, block_ts);
    run_tx(&mut ctx, locked_cell, header_dep, wire)
        .expect("transaction should succeed: timelock passed, sig non-zero");
}

/// PSCT passes but VM rejects: block timestamp is before unlock time.
/// Shows the PSCT / semantic boundary — the timelock is enforced by the VM only.
#[test]
fn test_psct_passes_but_vm_rejects_timelock_not_met() {
    let idl = load_timelock_idl();

    let unlock_after_ms: u64 = 9_999_999_999_999; // far in the future
    let block_ts: u64 = 1_000;

    let wire = encode_timelock_witness(&FAKE_SIG, unlock_after_ms, &[]);

    let client = IdlClient::new();
    client
        .validate_witness_bytes(&idl.witness, &wire)
        .expect("PSCT should pass: structure is valid even if timelock not met");

    let args = build_args(None);
    let (mut ctx, locked_cell, header_dep) = setup_timelock_cell(args, block_ts);
    let err = run_tx(&mut ctx, locked_cell, header_dep, wire).unwrap_err();
    assert!(
        err.to_string().contains("error code 12"),
        "expected TimelockNotMet (12), got: {err}"
    );
}

/// PSCT passes but VM rejects: signature is all zeros.
#[test]
fn test_psct_passes_but_vm_rejects_zero_signature() {
    let idl = load_timelock_idl();

    let zero_sig = [0u8; 65];
    let block_ts: u64 = 2_000_000;
    let wire = encode_timelock_witness(&zero_sig, 0, &[]);

    let client = IdlClient::new();
    client
        .validate_witness_bytes(&idl.witness, &wire)
        .expect("PSCT should pass: zero sig is structurally valid");

    let args = build_args(None);
    let (mut ctx, locked_cell, header_dep) = setup_timelock_cell(args, block_ts);
    let err = run_tx(&mut ctx, locked_cell, header_dep, wire).unwrap_err();
    assert!(
        err.to_string().contains("error code 11"),
        "expected SignatureInvalid (11), got: {err}"
    );
}

/// Full flow: non-empty extra payload whose hash matches the commitment in args.
#[test]
fn test_psct_validate_then_execute_with_extra_payload() {
    let idl = load_timelock_idl();

    let extra_payload = b"session_token_or_merkle_proof";
    let commitment: [u8; 32] = blake2b_256(extra_payload);
    let block_ts: u64 = 2_000_000;

    let wire = encode_timelock_witness(&FAKE_SIG, 0, extra_payload);

    let client = IdlClient::new();
    let validated = client
        .validate_witness_bytes(&idl.witness, &wire)
        .expect("witness with extra should pass PSCT");

    assert_eq!(
        validated[2].value,
        DecodedValue::Bytes(extra_payload.to_vec())
    );

    let args = build_args(Some(commitment));
    let (mut ctx, locked_cell, header_dep) = setup_timelock_cell(args, block_ts);
    run_tx(&mut ctx, locked_cell, header_dep, wire)
        .expect("transaction should succeed: commitment matches extra hash");
}

/// PSCT passes but VM rejects: extra hash mismatches commitment in args.
#[test]
fn test_psct_passes_but_vm_rejects_extra_hash_mismatch() {
    let idl = load_timelock_idl();

    let real_payload = b"correct_payload";
    let wrong_payload = b"wrong_payload";
    let block_ts: u64 = 2_000_000;

    let commitment: [u8; 32] = blake2b_256(real_payload);
    let wire = encode_timelock_witness(&FAKE_SIG, 0, wrong_payload);

    let client = IdlClient::new();
    client
        .validate_witness_bytes(&idl.witness, &wire)
        .expect("PSCT should pass: structure valid even with wrong hash");

    let args = build_args(Some(commitment));
    let (mut ctx, locked_cell, header_dep) = setup_timelock_cell(args, block_ts);
    let err = run_tx(&mut ctx, locked_cell, header_dep, wire).unwrap_err();
    assert!(
        err.to_string().contains("error code 4"),
        "expected Encoding error (4) on hash mismatch, got: {err}"
    );
}

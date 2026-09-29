use std::{collections::HashMap, str::FromStr};

use ckb_hash::blake2b_256;
use ckb_idl_client::IdlClient;
use ckb_sdk::{
    Address, CkbRpcClient, ScriptId,
    constants::SIGHASH_TYPE_HASH,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{CapacityBalancer, TxBuilder, transfer::CapacityTransferBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
};
use ckb_types::{
    bytes::Bytes,
    core::{DepType, ScriptHashType, TransactionView},
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::{Builder, Entity, Pack, Unpack},
};
use secp256k1::SecretKey;

use crate::config::Config;
use crate::deploy_script::{deploy_script, fetch_code_cell_data};

// ─────────────────────────────────────────────────────────────────────────────
// Generic infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/// Build and submit a transaction that spends one IDL-locked cell.
///
/// Callers are responsible for:
///   - Producing the wire-encoded `witness_bytes` for the locked cell
///   - Running IDL verification and structural validation before calling here
///   - Passing any extra `CellDep`s required by the script (e.g. header deps)
///
/// This function handles everything else: balancing fee-payer inputs, injecting
/// the locked cell as input[0], adding the code cell dep, and re-signing the
/// secp256k1 fee-payer inputs after the injection.
pub fn spend_locked_cell(
    ckb_rpc: &str,
    spender_address: &str,
    spender_key: [u8; 32],
    code_cell_outpoint: OutPoint,
    locked_cell_outpoint: OutPoint,
    // Pre-built wire bytes to place in WitnessArgs.lock for the locked cell.
    witness_bytes: Vec<u8>,
    // Any extra cell deps the script needs beyond the code cell dep itself.
    extra_cell_deps: Vec<CellDep>,
) -> anyhow::Result<()> {
    let ckb_client = CkbRpcClient::new(ckb_rpc);

    let spender = Address::from_str(spender_address)
        .map_err(|e| anyhow::anyhow!("invalid spender address: {e}"))?;
    let spender_lock: Script = spender.payload().into();

    // Code cell dep — the deployed script binary
    let code_cell_dep = CellDep::new_builder()
        .out_point(code_cell_outpoint.clone())
        .dep_type(DepType::Code.into())
        .build();

    // Fetch code hash so we can register the script with the resolver
    let (code_hash_packed, _) = fetch_code_cell_data(&ckb_client, &code_cell_outpoint)?;

    let mut cell_dep_resolver = DefaultCellDepResolver::from_genesis(
        &ckb_client.get_block_by_number(0.into())?.unwrap().into(),
    )?;

    // Register the code dep under a placeholder script id so the SDK resolver
    // includes it when balancing. (We also append it explicitly below.)
    let placeholder_script = Script::new_builder()
        .code_hash(code_hash_packed)
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::new().pack())
        .build();
    let placeholder_script_id = ScriptId::new_data(placeholder_script.calc_script_hash().unpack());
    cell_dep_resolver.insert(
        placeholder_script_id,
        code_cell_dep.clone(),
        "locked-script".to_string(),
    );

    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    // Secp256k1 unlocker for fee-payer inputs
    let signer =
        SecpCkbRawKeySigner::new_with_secret_keys(vec![SecretKey::from_byte_array(&spender_key)?]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
    unlockers.insert(sighash_script_id, Box::new(sighash_unlocker));

    // Output: return capacity to the spender
    let output = CellOutput::new_builder()
        .capacity((61u64 * 100_000_000u64).pack())
        .lock(spender_lock.clone())
        .build();

    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(spender_lock, placeholder_witness, 1000);

    // Step A: balance the transaction (collects and signs fee-payer inputs)
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::new())]);
    let (balanced_tx, _) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;

    // Step B: inject locked cell as input[0] + its witness + all required deps.
    // This shifts fee-payer inputs to indices 1.., invalidating their signatures.
    let locked_input = CellInput::new_builder()
        .previous_output(locked_cell_outpoint)
        .build();

    let locked_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(witness_bytes)).pack())
        .build();

    let inputs: Vec<_> = std::iter::once(locked_input)
        .chain(balanced_tx.inputs())
        .collect();
    let witnesses: Vec<_> = std::iter::once(locked_witness.as_bytes().pack())
        .chain(balanced_tx.witnesses())
        .collect();
    // Append code dep + any script-specific extra deps
    let cell_deps: Vec<_> = balanced_tx
        .cell_deps()
        .into_iter()
        .chain(std::iter::once(code_cell_dep))
        .chain(extra_cell_deps)
        .collect();

    let unsigned_tx: TransactionView = balanced_tx
        .as_advanced_builder()
        .set_inputs(inputs)
        .set_witnesses(witnesses)
        .set_cell_deps(cell_deps)
        .build();

    // Step C: re-sign fee-payer inputs against the final transaction hash
    let (signed_tx, _) = {
        let signer2 = SecpCkbRawKeySigner::new_with_secret_keys(vec![SecretKey::from_byte_array(
            &spender_key,
        )?]);
        let sighash_unlocker2 = SecpSighashUnlocker::from(Box::new(signer2) as Box<_>);
        let sighash_script_id2 = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let mut unlockers2: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
        unlockers2.insert(sighash_script_id2, Box::new(sighash_unlocker2));
        ckb_sdk::tx_builder::unlock_tx(unsigned_tx, &tx_dep_provider, &unlockers2)?
    };

    let tx_hash = ckb_client.send_transaction(signed_tx.data().into(), None)?;
    println!("Spend tx hash: {:#x}", tx_hash);
    println!("Cell spent successfully.");

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// IDL verification + structural validation (shared)
// ─────────────────────────────────────────────────────────────────────────────

/// Verify the on-chain IDL commitment and structurally validate `wire_bytes`.
/// Returns the parsed field list on success.
pub fn verify_and_validate(
    code_hash: [u8; 32],
    code_cell_data: &[u8],
    idl_path: &str,
    wire_bytes: &[u8],
) -> anyhow::Result<ckb_idl_client::WitnessObject> {
    let idl_json_bytes = std::fs::read(idl_path)
        .map_err(|e| anyhow::anyhow!("failed to read IDL file at {idl_path}: {e}"))?;

    let mut idl_client = IdlClient::new();
    idl_client
        .verify(code_hash, &idl_json_bytes, code_cell_data)
        .map_err(|e| anyhow::anyhow!("IDL commitment verification failed: {e}"))?;
    println!("IDL commitment verified — IDL is authentic.");

    let validated = idl_client
        .validate_witness_bytes(idl_client.lock_witness_requirements(code_hash)?, wire_bytes)
        .map_err(|e| anyhow::anyhow!("witness validation failed: {e}"))?;

    println!("Witness structurally valid. Decoded fields:");
    for f in &validated {
        println!("  {}: {:?}", f.name, f.value);
    }

    Ok(validated)
}

// ─────────────────────────────────────────────────────────────────────────────
// Deploy helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Deploy `simple-lock` with IDL commitment appended.
pub fn deploy_simple_lock() -> anyhow::Result<OutPoint> {
    let cfg = Config::from_env()?;
    let secret_key = cfg.secret_key()?;

    println!("Deploying from: {}", cfg.address);
    println!("RPC endpoint:   {}", cfg.ckb_rpc);

    let code_outpoint = deploy_script(
        &cfg.ckb_rpc,
        &cfg.address,
        secret_key,
        "./build/release/simple-lock",
        Some("./contracts/simple-lock/idl.json"),
    )?;

    println!("Code outpoint tx: {:#x}", code_outpoint.tx_hash());
    Ok(code_outpoint)
}

/// Deploy `timelock-lock` with IDL commitment appended.
pub fn deploy_timelock_lock() -> anyhow::Result<OutPoint> {
    let cfg = Config::from_env()?;
    let secret_key = cfg.secret_key()?;

    println!("Deploying from: {}", cfg.address);
    println!("RPC endpoint:   {}", cfg.ckb_rpc);

    let code_outpoint = deploy_script(
        &cfg.ckb_rpc,
        &cfg.address,
        secret_key,
        "./build/release/timelock-lock",
        Some("./contracts/timelock-lock/idl.json"),
    )?;

    println!("Code outpoint tx: {:#x}", code_outpoint.tx_hash());
    Ok(code_outpoint)
}

// ─────────────────────────────────────────────────────────────────────────────
// simple-lock: spend
// ─────────────────────────────────────────────────────────────────────────────

/// Spend a simple-lock cell.
///
/// Args (positional):
///   <code_cell_tx_hash>   hex tx hash of the deployed simple-lock code cell
///   <preimage_hex>        hex-encoded preimage whose blake2b-256 = lock args
///   <idl_path>            path to the frozen IDL file
///   <locked_cell_tx_hash> hex tx hash of the cell to spend (index 0)
pub fn spend_simple_lock(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    let Config {
        ckb_rpc,
        address: spender_address,
        private_key_bytes: spender_key,
    } = cfg;

    let [
        string_code_cell_outpoint,
        string_preimage,
        string_idl_path,
        string_locked_cell_outpoint,
    ] = [args.next(), args.next(), args.next(), args.next()].map(|x| x.expect("Missing arg"));

    let bytes_code: [u8; 32] = hex::decode(&string_code_cell_outpoint)?.try_into().unwrap();
    let code_cell_outpoint = OutPoint::new(bytes_code.pack(), 0);

    let bytes_locked: [u8; 32] = hex::decode(&string_locked_cell_outpoint)?
        .try_into()
        .unwrap();
    let locked_cell_outpoint = OutPoint::new(bytes_locked.pack(), 0);

    let preimage_bytes = hex::decode(&string_preimage)?;
    let preimage: &[u8] = &preimage_bytes;

    let ckb_client = CkbRpcClient::new(&ckb_rpc);
    let (code_hash_packed, code_cell_data) =
        fetch_code_cell_data(&ckb_client, &code_cell_outpoint)?;
    let code_hash: [u8; 32] = code_hash_packed.unpack();
    println!("code_hash: {}", hex::encode(code_hash));

    // Wire encoding: 4-byte LE length prefix + preimage bytes
    let wire = encode_bytes_field(preimage);

    verify_and_validate(code_hash, &code_cell_data, &string_idl_path, &wire)?;

    spend_locked_cell(
        &ckb_rpc,
        &spender_address,
        spender_key,
        code_cell_outpoint,
        locked_cell_outpoint,
        wire,
        vec![], // no extra deps for simple-lock
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// timelock-lock: spend
// ─────────────────────────────────────────────────────────────────────────────

/// Spend a timelock-lock cell.
///
/// Args (positional):
///   <code_cell_tx_hash>   hex tx hash of the deployed timelock-lock code cell
///   <signing_key_hex>     hex private key whose public key is in args[0..33]
///   <unlock_after_ms>     u64 timestamp (must be ≤ current block timestamp)
///   <extra_hex>           hex extra payload, or "" for empty
///   <idl_path>            path to the frozen IDL file
///   <locked_cell_tx_hash> hex tx hash of the cell to spend (index 0)
pub fn spend_timelock_lock(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    let Config {
        ckb_rpc,
        address: spender_address,
        private_key_bytes: spender_key,
    } = cfg;

    let [
        string_code_cell_outpoint,
        string_signing_key,
        string_unlock_after_ms,
        string_extra,
        string_idl_path,
        string_locked_cell_outpoint,
    ] = [
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ]
    .map(|x| x.expect("Missing arg"));

    let bytes_code: [u8; 32] = hex::decode(&string_code_cell_outpoint)?.try_into().unwrap();
    let code_cell_outpoint = OutPoint::new(bytes_code.pack(), 0);

    let bytes_locked: [u8; 32] = hex::decode(&string_locked_cell_outpoint)?
        .try_into()
        .unwrap();
    let locked_cell_outpoint = OutPoint::new(bytes_locked.pack(), 0);

    let unlock_after_ms: u64 = string_unlock_after_ms
        .parse()
        .map_err(|_| anyhow::anyhow!("unlock_after_ms must be a u64"))?;

    let extra_bytes = if string_extra.is_empty() {
        vec![]
    } else {
        hex::decode(&string_extra)?
    };

    let signing_key_bytes: [u8; 32] = hex::decode(string_signing_key.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    let signing_key = SecretKey::from_byte_array(&signing_key_bytes)?;

    let ckb_client = CkbRpcClient::new(&ckb_rpc);
    let (code_hash_packed, code_cell_data) =
        fetch_code_cell_data(&ckb_client, &code_cell_outpoint)?;
    let code_hash: [u8; 32] = code_hash_packed.unpack();
    println!("code_hash: {}", hex::encode(code_hash));

    // ── Build a preliminary wire with a zero signature placeholder ────────────
    // Witness layout:
    //   [0..65]          signature  (fixed 65 bytes, no length prefix — secp256k1_sig)
    //   [65..73]         unlock_after_ms (u64 LE, no length prefix — uint64)
    //   [73..77+n]       extra length prefix (4 bytes LE) + extra bytes
    let wire_unsigned = encode_timelock_witness(&[0u8; 65], unlock_after_ms, &extra_bytes);

    verify_and_validate(code_hash, &code_cell_data, &string_idl_path, &wire_unsigned)?;

    // ── Build the full transaction with the placeholder witness ───────────────
    // We need the real tx hash to produce the final signature.
    // Strategy: build the tx once with the placeholder, extract the signing hash,
    // sign it, then patch the witness.
    //
    // The signing hash for CKB secp256k1 is the blake2b-256 of the serialised
    // transaction skeleton (inputs, outputs, cell_deps, header_deps, version) —
    // NOT including the witnesses. We compute it from the unsigned tx.
    //
    // For simplicity we use the transaction hash directly (tx.hash()), which is
    // what the timelock-lock placeholder implementation checks.
    let placeholder_wire = encode_timelock_witness(&[0u8; 65], unlock_after_ms, &extra_bytes);

    // Build the full tx so we can extract its hash
    let secp = secp256k1::Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &signing_key);
    let pubkey_compressed = pubkey.serialize(); // 33 bytes

    // Derive lock args from the signing key's public key
    let lock_args_hash = blake2b_256(pubkey_compressed);

    // We need to sign the tx hash.  Build a temporary tx to get the hash, then
    // sign it and rebuild with the real signature.
    let temp_wire = placeholder_wire.clone();

    // Get the tx hash by running spend_locked_cell in dry-run is not possible
    // without a separate RPC call. Instead we build the transaction manually
    // here to extract the hash before sending.
    let signed_wire = {
        // Build the transaction the same way spend_locked_cell does, extract
        // its hash, sign it, and produce the final wire bytes.
        let spender_addr = Address::from_str(&spender_address)
            .map_err(|e| anyhow::anyhow!("invalid spender address: {e}"))?;
        let spender_lock: Script = spender_addr.payload().into();

        let code_cell_dep = CellDep::new_builder()
            .out_point(code_cell_outpoint.clone())
            .dep_type(DepType::Code.into())
            .build();

        let mut cell_dep_resolver = DefaultCellDepResolver::from_genesis(
            &ckb_client.get_block_by_number(0.into())?.unwrap().into(),
        )?;
        let placeholder_script = Script::new_builder()
            .code_hash(code_hash_packed)
            .hash_type(ScriptHashType::Data1.into())
            .args(Bytes::from(lock_args_hash.to_vec()).pack())
            .build();
        let placeholder_script_id =
            ScriptId::new_data(placeholder_script.calc_script_hash().unpack());
        cell_dep_resolver.insert(
            placeholder_script_id,
            code_cell_dep.clone(),
            "timelock-lock".to_string(),
        );

        let header_dep_resolver = DefaultHeaderDepResolver::new(&ckb_rpc);
        let tx_dep_provider = DefaultTransactionDependencyProvider::new(&ckb_rpc, 10);

        let fee_signer =
            SecpCkbRawKeySigner::new_with_secret_keys(vec![SecretKey::from_byte_array(
                &spender_key,
            )?]);
        let fee_unlocker = SecpSighashUnlocker::from(Box::new(fee_signer) as Box<_>);
        let fee_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
        unlockers.insert(fee_script_id, Box::new(fee_unlocker));

        let output = CellOutput::new_builder()
            .capacity((61u64 * 100_000_000u64).pack())
            .lock(spender_lock.clone())
            .build();

        let mut cell_collector = DefaultCellCollector::new(&ckb_rpc);
        let ph_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build();
        let balancer = CapacityBalancer::new_simple(spender_lock, ph_witness, 1000);

        let builder = CapacityTransferBuilder::new(vec![(output, Bytes::new())]);
        let (balanced_tx, _) = builder.build_unlocked(
            &mut cell_collector,
            &cell_dep_resolver,
            &header_dep_resolver,
            &tx_dep_provider,
            &balancer,
            &unlockers,
        )?;

        let locked_input = CellInput::new_builder()
            .previous_output(locked_cell_outpoint.clone())
            .build();
        let placeholder_locked_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(temp_wire)).pack())
            .build();

        let inputs: Vec<_> = std::iter::once(locked_input)
            .chain(balanced_tx.inputs())
            .collect();
        let witnesses: Vec<_> = std::iter::once(placeholder_locked_witness.as_bytes().pack())
            .chain(balanced_tx.witnesses())
            .collect();
        let cell_deps: Vec<_> = balanced_tx
            .cell_deps()
            .into_iter()
            .chain(std::iter::once(code_cell_dep))
            .collect();

        let draft_tx: TransactionView = balanced_tx
            .as_advanced_builder()
            .set_inputs(inputs)
            .set_witnesses(witnesses)
            .set_cell_deps(cell_deps)
            .build();

        // Sign the transaction hash with the timelock signing key
        let tx_hash: [u8; 32] = draft_tx.hash().unpack();
        let message = secp256k1::Message::from_digest(tx_hash);
        let (rec_id, sig_bytes) = secp
            .sign_ecdsa_recoverable(&message, &signing_key)
            .serialize_compact();
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&sig_bytes);
        // RecoveryId is a newtype(u8) — extract the inner value directly
        let rec_id_byte: u8 = unsafe { std::mem::transmute::<_, u8>(rec_id) };
        signature[64] = rec_id_byte;

        println!(
            "Signed tx hash {} with pubkey {}",
            hex::encode(tx_hash),
            hex::encode(pubkey_compressed)
        );

        encode_timelock_witness(&signature, unlock_after_ms, &extra_bytes)
    };

    spend_locked_cell(
        &ckb_rpc,
        &spender_address,
        spender_key,
        code_cell_outpoint,
        locked_cell_outpoint,
        signed_wire,
        vec![], // header dep would go here if the contract loaded headers
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a variable-length bytes field: 4-byte LE length prefix + payload.
pub fn encode_bytes_field(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Encode the full timelock-lock witness wire format:
///   [0..65]   signature (fixed, no length prefix)
///   [65..73]  unlock_after_ms as u64 LE (fixed, no length prefix)
///   [73..]    extra as length-prefixed bytes
pub fn encode_timelock_witness(
    signature: &[u8; 65],
    unlock_after_ms: u64,
    extra: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(65 + 8 + 4 + extra.len());
    buf.extend_from_slice(signature);
    buf.extend_from_slice(&unlock_after_ms.to_le_bytes());
    buf.extend_from_slice(&encode_bytes_field(extra));
    buf
}

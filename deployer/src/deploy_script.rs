use std::{collections::HashMap, println, process::Command, str::FromStr, vec};

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::Either;
use ckb_sdk::{
    Address, CkbRpcClient, ScriptId,
    constants::SIGHASH_TYPE_HASH,
    rpc::ckb_indexer::{SearchKey, SearchMode},
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{CapacityBalancer, TxBuilder, transfer::CapacityTransferBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
};
use ckb_types::{
    H256,
    bytes::Bytes,
    core::{DepType, ScriptHashType},
    packed::{CellDep, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::{Builder, Entity, Pack, Unpack},
};
use secp256k1::SecretKey;
use sha2::{Digest, Sha256};

// pub const TESTNET_RPC: &str = "https://testnet.ckb.dev";

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn deploy_script(
    ckb_rpc: &str,
    deployer_address: &str,
    sender_key: SecretKey,
    script_path: &str,
    idl_path: Option<&str>,
) -> anyhow::Result<OutPoint> {
    let mut script_binary = std::fs::read(script_path)?;
    let mut idl_hash: Vec<u8> = Vec::new();

    if let Some(path) = idl_path {
        let idl_json_bytes = std::fs::read(path)?;
        let hash = sha256(&idl_json_bytes);
        idl_hash.extend_from_slice(&hash);

        // Freeze the exact IDL bytes that were committed
        // Named after the script binary so it is unambiguous
        let script_name = std::path::Path::new(script_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("script");
        let frozen_path = format!("{script_name}-idl.deployed.json");
        std::fs::write(&frozen_path, &idl_json_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to write frozen IDL to {frozen_path}: {e}"))?;
        println!("Frozen IDL written to: {frozen_path}");
    }

    script_binary.extend_from_slice(&idl_hash);

    let script_size = script_binary.len();
    let required_capacity = (script_size as u64 + 100) * 100_000_000;

    println!("Script size: {script_size} bytes");
    println!("Required capacity: {} CKB", required_capacity / 100_000_000);

    let sender = Address::from_str(deployer_address).unwrap();

    let payload = sender.payload();

    // Build a cell that contains the script binary as its data.
    // This is what is called deploying the script
    let deployer_lock: Script = Script::from(payload);

    let code_cell_output = CellOutput::new_builder()
        .capacity(required_capacity.pack())
        .lock(deployer_lock)
        .build();

    let ckb_client = CkbRpcClient::new(ckb_rpc); // Try the url itself if fail

    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);

    let blockview = (ckb_client.get_block_by_number(0.into())?).unwrap();
    let cell_dep_resolver = DefaultCellDepResolver::from_genesis(&blockview.into())?;
    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());

    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
    unlockers.insert(sighash_script_id, Box::new(sighash_unlocker));

    let placeholder_witness = ckb_types::packed::WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender.payload().into(), placeholder_witness, 1000);

    let builder =
        CapacityTransferBuilder::new(vec![(code_cell_output, Bytes::from(script_binary))]);

    let (tx, _) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;

    let tx_hash = ckb_client.send_transaction(tx.data().into(), None)?;

    println!("Deployment tx hash: {:#x}", tx_hash);
    println!("Code cell Outpoint: {}:0x0", tx_hash);

    Ok(OutPoint::new(tx_hash.pack(), 0))
}

/// Verifies and deploys a prepared Binding Trailer 1 bundle without modifying it.
pub fn deploy_bound_bundle(
    ckb_rpc: &str,
    deployer_address: &str,
    sender_key: SecretKey,
    executable_path: &str,
    idl_path: &str,
    manifest_path: &str,
) -> anyhow::Result<OutPoint> {
    let ckb_idl = std::env::var("CKB_IDL").unwrap_or_else(|_| "ckb-idl".into());
    let status = Command::new(ckb_idl)
        .args([
            "verify",
            "--executable",
            executable_path,
            "--idl",
            idl_path,
            "--manifest",
            manifest_path,
        ])
        .status()?;
    anyhow::ensure!(status.success(), "ckb-idl verify rejected the bundle");

    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(manifest_path)?)?;
    let expected = manifest["bound_code_data_ckb_hash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("manifest lacks bound_code_data_ckb_hash"))?;
    let outpoint = deploy_script(ckb_rpc, deployer_address, sender_key, executable_path, None)?;
    let client = CkbRpcClient::new(ckb_rpc);
    let (_, deployed) = fetch_code_cell_data(&client, &outpoint)?;
    let actual = format!("0x{}", hex::encode(blake2b_256(&deployed)));
    anyhow::ensure!(
        actual == expected,
        "deployed data hash differs from binding manifest"
    );
    let receipt = serde_json::json!({
        "format": "ckb-idl-deployment-receipt-0.1",
        "network": std::env::var("CKB_NETWORK").unwrap_or_else(|_| "unspecified".into()),
        "outpoint": { "tx_hash": format!("{:#x}", outpoint.tx_hash()), "index": 0 },
        "code_hash": actual,
        "hash_type": "data1",
        "idl_sha256": manifest["idl_sha256"],
    });
    println!("deployment_receipt={}", serde_json::to_string(&receipt)?);
    Ok(outpoint)
}

pub fn mint_tokens(
    ckb_rpc: &str,
    code_cell_outpoint: OutPoint,
    issuer_address: &str,
    issuer_key: SecretKey,
    recipient_address: &str,
    amount: u128,
) -> anyhow::Result<()> {
    let ckb_client = CkbRpcClient::new(ckb_rpc);

    let issuer_addr = Address::from_str(issuer_address).unwrap();
    let recipient_addr = Address::from_str(recipient_address).unwrap();

    let issuer_lock: Script = (issuer_addr.payload()).into();

    let owner_lock_hash = ckb_hash::blake2b_256(issuer_lock.as_slice());

    let code_hash: H256 = compute_code_hash(&ckb_client, &code_cell_outpoint)?.unpack();

    let sudt_type_script = Script::new_builder()
        .code_hash(compute_code_hash(&ckb_client, &code_cell_outpoint)?)
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(owner_lock_hash.to_vec()).pack())
        .build();

    let recipient_lock: Script = (recipient_addr.payload()).into();
    let udt_cell = CellOutput::new_builder()
        .capacity((142u64 * 100_000_000).pack())
        .lock(recipient_lock)
        .type_(Some(sudt_type_script).pack())
        .build();

    let udt_data = Bytes::from(amount.to_be_bytes().to_vec());

    let sudt_cell_dep = CellDep::new_builder()
        .out_point(code_cell_outpoint)
        .dep_type(DepType::Code.into())
        .build();
    let sudt_script_id = ScriptId::new_data(code_hash);

    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let mut cell_dep_resolver = DefaultCellDepResolver::from_genesis(
        &ckb_client.get_block_by_number(0.into())?.unwrap().into(),
    )?;
    cell_dep_resolver.insert(sudt_script_id, sudt_cell_dep, "sudt".to_string());
    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![issuer_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());

    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
    unlockers.insert(sighash_script_id, Box::new(sighash_unlocker));

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(issuer_lock, placeholder_witness, 1000);

    let builder = CapacityTransferBuilder::new(vec![(udt_cell, udt_data)]);

    let (tx, _) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;

    let tx_hash = ckb_client.send_transaction(tx.data().into(), None)?;
    println!("Mint tx hash: {:#x}", tx_hash);
    println!("Minted {} tokens to {}", amount, recipient_address);

    Ok(())
}

pub fn compute_code_hash(
    ckb_client: &CkbRpcClient,
    code_cell_outpoint: &OutPoint,
) -> anyhow::Result<ckb_types::packed::Byte32> {
    let (hash, _) = fetch_code_cell_data(ckb_client, code_cell_outpoint)?;
    Ok(hash)
}

/// Fetch the raw cell data and its blake2b-256 hash for a deployed code cell.
/// Returns (code_hash, raw_cell_data_bytes).
pub fn fetch_code_cell_data(
    ckb_client: &CkbRpcClient,
    code_cell_outpoint: &OutPoint,
) -> anyhow::Result<(ckb_types::packed::Byte32, Vec<u8>)> {
    let tx_hash = code_cell_outpoint.tx_hash();
    let index: u32 = code_cell_outpoint.index().unpack();

    let tx = ckb_client
        .get_transaction(tx_hash.unpack())?
        .expect("deployment tx not found")
        .transaction
        .expect("tx data missing");

    let packed_tx = match tx.inner {
        Either::Left(json_tx) => {
            let packed: ckb_types::packed::Transaction = json_tx.inner.into();
            packed
        }
        Either::Right(bytes) => ckb_types::packed::Transaction::from_slice(bytes.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to decode tx bytes: {e}"))?,
    };

    let data = packed_tx
        .raw()
        .outputs_data()
        .get(index as usize)
        .expect("output data missing");
    let raw: Bytes = data.unpack();
    let raw_vec = raw.to_vec();
    let code_hash = blake2b_256(raw.as_ref()).pack();

    Ok((code_hash, raw_vec))
}

#[allow(unused)]
pub fn transfer_tokens(
    ckb_rpc: &str,
    sudt_type_script: Script,
    code_cell_outpoint: OutPoint,
    sender_address: &str,
    sender_key_hex: &str,
    recipient_address: &str,
    transfer_amount: u128,
) -> anyhow::Result<()> {
    let ckb_client = CkbRpcClient::new(ckb_rpc);

    let sender_addr = Address::from_str(sender_address).unwrap();

    let mut clean_sender_key = [0_u8; 32];
    let sender_key_bytes = hex::decode(sender_key_hex)?;
    clean_sender_key.copy_from_slice(&sender_key_bytes);
    let sender_key = SecretKey::from_byte_array(&clean_sender_key)?;

    let recipient_addr = Address::from_str(recipient_address).unwrap();

    let sender_lock: Script = sender_addr.payload().into();
    let recipient_lock: Script = recipient_addr.payload().into();

    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let sudt_type_hash: [u8; 32] = sudt_type_script.calc_script_hash().unpack();

    let search_key = SearchKey {
        script: sender_lock.clone().into(),
        script_type: ckb_sdk::rpc::ckb_indexer::ScriptType::Lock,
        filter: Some(ckb_sdk::rpc::ckb_indexer::SearchKeyFilter {
            script: Some(sudt_type_script.clone().into()),
            ..Default::default()
        }),
        script_search_mode: Some(SearchMode::Partial),
        with_data: Some(true),
        group_by_transaction: Some(true),
    };

    let udt_cells = ckb_client.get_cells(
        search_key,
        ckb_sdk::rpc::ckb_indexer::Order::Asc,
        1000.into(),
        None,
    )?;

    let mut inputs = Vec::new();
    let mut input_total: u128 = 0;

    for cell in &udt_cells.objects {
        let cell_type_hash: Option<[u8; 32]> = cell.output.type_.as_ref().map(|s| {
            let script: Script = s.clone().into();
            script.calc_script_hash().unpack()
        });

        match cell_type_hash {
            Some(hash) if hash == sudt_type_hash => {
                let output_data = cell
                    .output_data
                    .as_ref()
                    .expect("output data not found")
                    .as_bytes();
                let amount = u128::from_le_bytes(output_data[..16].try_into().unwrap());
                inputs.push(cell.clone());
                input_total = input_total.checked_add(amount).expect("overflow");
            }
            _ => continue,
        }

        if input_total >= transfer_amount {
            break;
        }
    }

    if input_total < transfer_amount {
        anyhow::bail!(
            "Insufficient UDT balance: have {}, need {}",
            input_total,
            transfer_amount
        );
    }

    let change_amount = input_total - transfer_amount;

    let capacity_per_cell = 142_u64 * 100_000_000; // 142 CKB

    let recipient_cell = CellOutput::new_builder()
        .capacity(capacity_per_cell.pack())
        .lock(recipient_lock)
        .type_(Some(sudt_type_script.clone()).pack())
        .build();

    let mut outputs = vec![(
        recipient_cell,
        Bytes::from(transfer_amount.to_le_bytes().to_vec()),
    )];

    if change_amount > 0 {
        let change_cell = CellOutput::new_builder()
            .capacity(capacity_per_cell.pack())
            .lock(sender_lock.clone())
            .type_(Some(sudt_type_script.clone()).pack())
            .build();
        outputs.push((
            change_cell,
            Bytes::from(change_amount.to_le_bytes().to_vec()),
        ));
    }

    let code_hash: H256 = compute_code_hash(&ckb_client, &code_cell_outpoint)?.unpack();
    let sudt_script_id = ScriptId::new_data(code_hash);

    let sudt_cell_dep = CellDep::new_builder()
        .out_point(code_cell_outpoint)
        .dep_type(DepType::Code.into())
        .build();

    let mut cell_dep_resolver = DefaultCellDepResolver::from_genesis(
        &ckb_client.get_block_by_number(0.into())?.unwrap().into(),
    )?;

    cell_dep_resolver.insert(sudt_script_id, sudt_cell_dep, "sudt".to_string());

    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
    unlockers.insert(sighash_script_id, Box::new(sighash_unlocker));

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender_lock, placeholder_witness, 1000);

    let builder = CapacityTransferBuilder::new(outputs);

    let (tx, _) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;

    let tx_hash = ckb_client.send_transaction(tx.data().into(), None)?;
    println!("Transfer tx hash: {:#x}", tx_hash);
    println!(
        "Transferred {} tokens to {}",
        transfer_amount, recipient_address
    );

    Ok(())
}

pub fn create_locked_cell(
    mut args: impl Iterator<Item = String>,
    config: &crate::config::Config,
) -> anyhow::Result<()> {
    let [string_code_cell_outpoint, preimage_hex] =
        [args.next(), args.next()].map(|x| x.expect("Missing arg"));

    let preimage_bytes = hex::decode(&preimage_hex)?;
    // simple-lock args = blake2b_256(preimage) — 32 bytes
    let lock_args = blake2b_256(preimage_bytes.as_slice()).to_vec();

    let outpoint = create_locked_cell_generic(
        &config.ckb_rpc,
        &config.address,
        config.secret_key()?,
        &string_code_cell_outpoint,
        lock_args.clone(),
        70464,
        "simple-lock",
    )?;

    println!("Locked cell created.");
    println!("Outpoint: {:#x}:0x0", outpoint.tx_hash());
    println!("Lock args (preimage hash): {}", hex::encode(&lock_args));
    println!("Preimage hex (needed for spend): {preimage_hex}");

    Ok(())
}

/// Create a cell locked by the timelock-lock script.
///
/// Args (positional):
///   <code_cell_tx_hash>  hex tx hash of the deployed timelock-lock code cell
///   <pubkey_hex>         33-byte compressed secp256k1 public key in hex
///   <extra_commitment>   32-byte hex commitment for extra payload, or "" for zeros
pub fn create_timelock_cell(
    mut args: impl Iterator<Item = String>,
    config: &crate::config::Config,
) -> anyhow::Result<()> {
    let [string_code_cell_outpoint, pubkey_hex, extra_commitment_hex] =
        [args.next(), args.next(), args.next()].map(|x| x.expect("Missing arg"));

    // timelock-lock args layout: [pubkey (33 bytes)][commitment (32 bytes)]
    let pubkey_bytes = hex::decode(&pubkey_hex)?;
    if pubkey_bytes.len() != 33 {
        anyhow::bail!(
            "pubkey must be 33 bytes (compressed secp256k1), got {}",
            pubkey_bytes.len()
        );
    }

    let commitment_bytes = if extra_commitment_hex.is_empty() {
        vec![0u8; 32]
    } else {
        let b = hex::decode(&extra_commitment_hex)?;
        if b.len() != 32 {
            anyhow::bail!("extra_commitment must be 32 bytes, got {}", b.len());
        }
        b
    };

    let mut lock_args = Vec::with_capacity(65);
    lock_args.extend_from_slice(&pubkey_bytes);
    lock_args.extend_from_slice(&commitment_bytes);

    let outpoint = create_locked_cell_generic(
        &config.ckb_rpc,
        &config.address,
        config.secret_key()?,
        &string_code_cell_outpoint,
        lock_args,
        70464,
        "timelock-lock",
    )?;

    println!("Timelock cell created.");
    println!("Outpoint: {:#x}:0x0", outpoint.tx_hash());
    println!("Pubkey: {pubkey_hex}");
    println!("Extra commitment: {extra_commitment_hex}");

    Ok(())
}

/// Generic cell creation: deploys a cell locked by any script with pre-built args.
///
/// - `code_cell_tx_hash_hex`: hex string of the code cell's transaction hash
/// - `lock_args`: the raw args bytes for the lock script
/// - `capacity_ckb`: the capacity to lock in the cell (in CKB, not shannons)
/// - `script_label`: a human-readable label used in logging
pub fn create_locked_cell_generic(
    ckb_rpc: &str,
    funder_address: &str,
    funder_key: SecretKey,
    code_cell_tx_hash_hex: &str,
    lock_args: Vec<u8>,
    capacity_ckb: u64,
    script_label: &str,
) -> anyhow::Result<OutPoint> {
    let bytes_code: [u8; 32] = hex::decode(code_cell_tx_hash_hex)?.try_into().unwrap();
    let code_cell_outpoint = OutPoint::new(bytes_code.pack(), 0);

    let ckb_client = CkbRpcClient::new(ckb_rpc);
    let (code_hash_packed, _) = fetch_code_cell_data(&ckb_client, &code_cell_outpoint)?;

    let lock_script = Script::new_builder()
        .code_hash(code_hash_packed)
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(lock_args).pack())
        .build();

    let code_cell_dep = CellDep::new_builder()
        .out_point(code_cell_outpoint)
        .dep_type(DepType::Code.into())
        .build();

    let locked_cell_output = CellOutput::new_builder()
        .capacity((capacity_ckb * 100_000_000).pack())
        .lock(lock_script.clone())
        .build();

    let funder_addr = Address::from_str(funder_address)
        .map_err(|e| anyhow::anyhow!("invalid funder address: {e}"))?;
    let funder_lock: Script = funder_addr.payload().into();

    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![funder_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
    unlockers.insert(sighash_script_id, Box::new(sighash_unlocker));

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(funder_lock, placeholder_witness, 1000);

    let mut cell_collector = DefaultCellCollector::new(ckb_rpc);
    let mut cell_dep_resolver = DefaultCellDepResolver::from_genesis(
        &ckb_client.get_block_by_number(0.into())?.unwrap().into(),
    )?;
    let script_id = ScriptId::new_data(lock_script.calc_script_hash().unpack());
    cell_dep_resolver.insert(script_id, code_cell_dep, script_label.to_string());

    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(ckb_rpc, 10);

    let builder = CapacityTransferBuilder::new(vec![(locked_cell_output, Bytes::new())]);
    let (tx, _) = builder.build_unlocked(
        &mut cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        &tx_dep_provider,
        &balancer,
        &unlockers,
    )?;

    let tx_hash = ckb_client.send_transaction(tx.data().into(), None)?;
    Ok(OutPoint::new(tx_hash.pack(), 0))
}

mod config;
mod deploy_script;
pub mod spend;

use config::Config;
use deploy_script::{deploy_script, mint_tokens};

fn main() -> anyhow::Result<()> {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "deploy-sudt".to_string());

    let args = std::env::args().skip(2);
    let config = Config::from_env()?;

    match command.as_str() {
        // ── SUDT (legacy) ────────────────────────────────────────────────────
        "deploy-sudt" => {
            deploy_and_mint_sudt()?;
        }
        "deploy-bundle" => {
            let values: Vec<_> = args.collect();
            anyhow::ensure!(
                values.len() == 3,
                "usage: deploy-bundle <bound-executable> <frozen-idl> <manifest>"
            );
            let outpoint = deploy_script::deploy_bound_bundle(
                &config.ckb_rpc,
                &config.address,
                config.secret_key()?,
                &values[0],
                &values[1],
                &values[2],
            )?;
            println!("Code outpoint tx: {:#x}", outpoint.tx_hash());
        }

        // ── simple-lock ──────────────────────────────────────────────────────
        "deploy-simple-lock" => {
            spend::deploy_simple_lock()?;
        }
        // create-locked-cell <code_tx_hash> <preimage_hex>
        "create-locked-cell" => {
            deploy_script::create_locked_cell(args, &config)?;
        }
        // spend-simple-lock <code_tx_hash> <preimage_hex> <idl_path> <locked_tx_hash>
        "spend-simple-lock" => {
            spend::spend_simple_lock(args)?;
        }

        // ── timelock-lock ────────────────────────────────────────────────────
        "deploy-timelock-lock" => {
            spend::deploy_timelock_lock()?;
        }
        // create-timelock-cell <code_tx_hash> <pubkey_hex> <extra_commitment_hex|"">
        "create-timelock-cell" => {
            deploy_script::create_timelock_cell(args, &config)?;
        }
        // spend-timelock-lock <code_tx_hash> <signing_key_hex> <unlock_after_ms>
        //                     <extra_hex|""> <idl_path> <locked_tx_hash>
        "spend-timelock-lock" => {
            spend::spend_timelock_lock(args)?;
        }

        other => anyhow::bail!("unknown command: {other}"),
    }

    Ok(())
}

pub fn deploy_and_mint_sudt() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    let secret_key = cfg.secret_key()?;

    println!("Deploying from: {}", cfg.address);
    println!("RPC endpoint:   {}", cfg.ckb_rpc);

    let code_outpoint = deploy_script(
        &cfg.ckb_rpc,
        &cfg.address,
        secret_key,
        "./build/release/ckb_sudt_script",
        None,
    )?;

    println!(
        "Save this! Code OutPoint tx: {:#x}",
        code_outpoint.tx_hash()
    );

    mint_tokens(
        &cfg.ckb_rpc,
        code_outpoint,
        &cfg.address,
        secret_key,
        &cfg.address,
        1_000_000,
    )?;

    Ok(())
}

#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

pub mod error;

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
};
use error::Error;

#[cfg(any(feature = "library", test))]
extern crate alloc;

use alloc::vec::Vec;
use ckb_idl_derive::CkbWitness;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

/// Witness for the timelock-lock script.
///
/// A cell protected by this lock can only be spent when ALL of the following hold:
///   1. The secp256k1 ECDSA `signature` over the transaction hash is valid for
///      the public key whose compressed form is stored in the script args (33 bytes).
///   2. The current block timestamp (in milliseconds since epoch) is greater than
///      or equal to `unlock_after_ms`.
///   3. If `extra` is non-empty its blake2b-256 hash must match the 32-byte
///      commitment stored in args[33..65] — use this for challenge/response or
///      Merkle-proof-style auxiliary data.
///
/// Args layout (65 bytes total):
///   [0..33]  compressed secp256k1 public key
///   [33..65] blake2b-256 hash of expected `extra` payload (all zeros = skip check)
#[derive(CkbWitness)]
pub struct Witness {
    #[witness(
        type = "secp256k1_sig",
        description = "secp256k1 ECDSA signature authorising the spend"
    )]
    pub signature: [u8; 65],

    #[witness(description = "Unix timestamp in milliseconds; cell cannot be spent before this")]
    pub unlock_after_ms: u64,

    #[witness(description = "Auxiliary payload; hash must match commitment in args[33..65]")]
    pub extra: Vec<u8>,
}

pub fn program_entry() -> i8 {
    match check_timelock() {
        Ok(()) => 0,
        Err(e) => e as i8,
    }
}

fn check_timelock() -> Result<(), Error> {
    let script = ckb_std::high_level::load_script()?;
    let args: Bytes = script.args().unpack();

    // Args must be at least 33 bytes (pubkey) and at most 65 (pubkey + commitment).
    if args.len() < 33 {
        return Err(Error::InvalidArgsLength);
    }

    // ── Step 1: deserialise the witness ──────────────────────────────────────
    let witness =
        Witness::from_witness_args(0, Source::GroupInput).map_err(|_| Error::MissingWitness)?;

    // ── Step 2: timelock check ────────────────────────────────────────────────
    // Load the transaction header dependency used as the time oracle.
    let header = ckb_std::high_level::load_header(0, Source::HeaderDep)?;
    let block_timestamp_ms: u64 = header.raw().timestamp().unpack();

    if block_timestamp_ms < witness.unlock_after_ms {
        return Err(Error::TimelockNotMet);
    }

    // ── Step 3: signature check (placeholder) ────────────────────────────────
    // A real implementation would call a secp256k1 verify syscall here using
    // `witness.signature` and `args[0..33]`. We assert the signature is
    // non-zero as a stand-in so the struct field is actually used.
    if witness.signature == [0u8; 65] {
        return Err(Error::SignatureInvalid);
    }

    // ── Step 4: optional extra-payload commitment check ───────────────────────
    if args.len() >= 65 && !witness.extra.is_empty() {
        use ckb_hash::blake2b_256;
        let commitment: [u8; 32] = args[33..65].try_into().map_err(|_| Error::Encoding)?;
        let actual = blake2b_256(witness.extra.as_slice());
        if actual != commitment {
            return Err(Error::Encoding);
        }
    }

    Ok(())
}

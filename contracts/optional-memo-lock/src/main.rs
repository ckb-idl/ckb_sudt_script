#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

mod error;

use alloc::vec::Vec;
use ckb_hash::blake2b_256;
use ckb_idl_derive::CkbWitness;
use ckb_std::{ckb_constants::Source, ckb_types::{bytes::Bytes, prelude::*}};
use error::Error;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

/// The trailing optional field exercises the current exhaustion-based option encoding.
#[derive(CkbWitness)]
pub struct Witness {
    pub proof: Vec<u8>,
    #[witness(required = false, description = "Optional wallet-visible memo")]
    pub memo: Option<Vec<u8>>,
}

pub fn program_entry() -> i8 { match verify() { Ok(()) => 0, Err(error) => error as i8 } }

fn verify() -> Result<(), Error> {
    let args: Bytes = ckb_std::high_level::load_script()?.args().unpack();
    if args.len() != 32 { return Err(Error::InvalidArgs); }
    let expected: [u8; 32] = args.as_ref().try_into().map_err(|_| Error::Encoding)?;
    let witness = Witness::from_witness_args(0, Source::GroupInput).map_err(|_| Error::MissingWitness)?;
    if blake2b_256(&witness.proof) != expected { return Err(Error::HashMismatch); }
    if witness.memo.as_ref().is_some_and(|memo| memo.len() > 1024) { return Err(Error::MemoTooLarge); }
    Ok(())
}

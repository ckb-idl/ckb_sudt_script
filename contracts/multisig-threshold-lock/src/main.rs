#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

mod error;

use alloc::vec::Vec;
use ckb_idl_derive::CkbWitness;
use ckb_std::{ckb_constants::Source, ckb_types::{bytes::Bytes, prelude::*}};
use error::Error;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

/// A typed-vector exercise. Args contain a little-endian u16 threshold.
#[derive(CkbWitness)]
pub struct Witness { pub signatures: Vec<[u8; 65]> }

pub fn program_entry() -> i8 { match verify() { Ok(()) => 0, Err(error) => error as i8 } }

fn verify() -> Result<(), Error> {
    let args: Bytes = ckb_std::high_level::load_script()?.args().unpack();
    if args.len() != 2 { return Err(Error::InvalidArgs); }
    let threshold = u16::from_le_bytes(args.as_ref().try_into().map_err(|_| Error::Encoding)?);
    let witness = Witness::from_witness_args(0, Source::GroupInput).map_err(|_| Error::MissingWitness)?;
    if threshold == 0 || witness.signatures.len() < threshold as usize || witness.signatures.iter().any(|signature| *signature == [0; 65]) {
        return Err(Error::ThresholdNotMet);
    }
    Ok(())
}

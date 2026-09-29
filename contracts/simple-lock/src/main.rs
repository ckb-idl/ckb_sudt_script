#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

pub mod error;
mod witness;

#[cfg(any(feature = "library", test))]
extern crate alloc;

use ckb_hash::blake2b_256;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
};
use error::Error;
use witness::Witness;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

pub fn program_entry() -> i8 {
    match check_hash() {
        Ok(()) => 0,
        Err(e) => e as i8,
    }
}

fn check_hash() -> Result<(), Error> {
    let script = ckb_std::high_level::load_script()?;
    let args: Bytes = script.args().unpack();

    // Args must be exactly 32 bytes — the expected blake2b-256 hash of the preimage.
    if args.len() != 32 {
        return Err(Error::InvalidArgsLength);
    }
    let expected: [u8; 32] = args[..32].try_into().map_err(|_| Error::Encoding)?;

    // Deserialise the witness — the struct drives the layout, not raw byte wrangling.
    let witness =
        Witness::from_witness_args(0, Source::GroupInput).map_err(|_| Error::MissingWitness)?;

    // Hash the preimage and compare.
    let actual = blake2b_256(witness.preimage.as_slice());

    if actual == expected {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

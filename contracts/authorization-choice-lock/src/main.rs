#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

mod error;

use ckb_hash::blake2b_256;
use ckb_std::{ckb_constants::Source, ckb_types::{bytes::Bytes, prelude::*}};
use error::Error;
use authorization_choice_lock::witness::{Authorization, Witness};

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

pub fn program_entry() -> i8 { match verify() { Ok(()) => 0, Err(error) => error as i8 } }

fn verify() -> Result<(), Error> {
    let args: Bytes = ckb_std::high_level::load_script()?.args().unpack();
    let witness = Witness::from_witness_args(0, Source::GroupInput).map_err(|_| Error::MissingWitness)?;
    match (&args[..], witness.authorization) {
        ([1, expected @ ..], Authorization::Preimage(auth)) if expected.len() == 32 => {
            let expected: [u8; 32] = expected.try_into().map_err(|_| Error::Encoding)?;
            if blake2b_256(&auth.preimage) == expected { Ok(()) } else { Err(Error::InvalidAuthorization) }
        }
        ([2], Authorization::Signature(auth)) if auth.signature != [0; 65] => Ok(()),
        _ => Err(Error::InvalidArgs),
    }
}

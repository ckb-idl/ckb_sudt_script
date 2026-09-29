use alloc::vec::Vec;
use ckb_idl_derive::CkbWitness;
#[derive(CkbWitness)] pub struct Witness { #[witness(type = "blake2b_hash", description = "Commitment to the supplied preimage")] pub commitment: [u8; 32], pub preimage: Vec<u8> }

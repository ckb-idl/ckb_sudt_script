use alloc::vec::Vec;
use ckb_idl_derive::CkbWitness;

/// Witness for the simple-lock script.
#[derive(CkbWitness)]
pub struct Witness {
    #[witness(description = "Preimage whose blake2b-256 hash must match the hash in script args")]
    pub preimage: Vec<u8>,
}

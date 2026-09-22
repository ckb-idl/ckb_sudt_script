use alloc::vec::Vec;
use ckb_idl_derive::{CkbInnerWitness, CkbWitness};

#[derive(CkbInnerWitness)]
pub struct Authorization {
    #[witness(description = "secp256k1 ECDSA signature authorising the spend")]
    pub signature: [u8; 65],

    #[witness(description = "Unix timestamp in milliseconds; cell cannot be spent before this")]
    pub unlock_after_ms: u64,

    #[witness(
        required = false,
        description = "Optional auxiliary payload; hash must match commitment in args[33..65]"
    )]
    pub extra: Option<Vec<u8>>,
}

#[derive(CkbWitness)]
pub struct Witness {
    #[witness(description = "Replay-protection nonce")]
    pub nonce: u16,
    pub authorization: Authorization,
}

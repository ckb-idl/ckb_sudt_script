use alloc::vec::Vec;
use ckb_idl_derive::CkbWitness;
#[derive(CkbWitness)] pub struct Witness { #[witness(type = "secp256k1_sig", description = "secp256k1 ECDSA signature authorising the spend")] pub signature: [u8; 65], #[witness(description = "Unix timestamp in milliseconds; cell cannot be spent before this")] pub unlock_after_ms: u64, #[witness(description = "Auxiliary payload; hash must match commitment in args[33..65]")] pub extra: Vec<u8> }

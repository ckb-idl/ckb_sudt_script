use alloc::vec::Vec;
use ckb_idl_derive::CkbWitness;
#[derive(CkbWitness)] pub struct Witness { pub proof: Vec<u8>, #[witness(required = false, description = "Optional wallet-visible memo")] pub memo: Option<Vec<u8>> }

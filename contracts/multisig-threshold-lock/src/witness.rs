use alloc::vec::Vec;
use ckb_idl_derive::CkbWitness;
#[derive(CkbWitness)] pub struct Witness { pub signatures: Vec<[u8; 65]> }

use alloc::vec::Vec;
use ckb_idl_derive::{CkbInnerWitness, CkbWitness, CkbWitnessUnion};

#[derive(CkbInnerWitness)]
pub struct PreimageAuthorization {
    pub preimage: Vec<u8>,
}

#[derive(CkbInnerWitness)]
pub struct SignatureAuthorization {
    #[witness(type = "secp256k1_sig")]
    pub signature: [u8; 65],
}

#[derive(CkbWitnessUnion)]
pub enum Authorization {
    #[witness(tag = 1)]
    Preimage(PreimageAuthorization),
    #[witness(tag = 2)]
    Signature(SignatureAuthorization),
}

#[derive(CkbWitness)]
pub struct Witness {
    #[witness(union, description = "Selected authorization mechanism")]
    pub authorization: Authorization,
}

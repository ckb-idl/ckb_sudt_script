extern crate alloc;
#[path = "../src/witness.rs"] mod witness;
ckb_idl_export::export_idl_main!(witness::Witness);

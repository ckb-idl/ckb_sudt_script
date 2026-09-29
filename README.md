# ckb-lock-script

## IDL-enabled deployment

IDL-enabled contracts are packaged before deployment. The deployer must receive
the bound executable, frozen IDL, and binding manifest; it never appends an IDL
digest itself.

```text
make package CONTRACT=<name>
make package-all IDL_DIST_DIR=<name>
make test-bound CONTRACT=<name>
make deploy CONTRACT=<name>
```

`make package` builds the contract, exports canonical IDL, and binds it using
the local `ckb-idl` binary. `make deploy` verifies the bundle, submits the bound
bytes unchanged, checks the deployed data hash against the manifest, and emits
a separate JSON deployment receipt.

A research workspace demonstrating the CKB IDL system — a convention for CKB lock scripts to publish a machine-readable interface description alongside their deployed binary, enabling wallets and tooling to validate witness encoding before submitting transactions.

The workspace contains two IDL-enabled lock scripts, a sUDT type script, a deployer binary, and an integration test suite.

---

## What is the IDL system?

CKB lock scripts receive their spending conditions through a raw byte buffer (`WitnessArgs.lock`). Without external documentation, wallets and tooling cannot know what the script expects — they must either have hard-coded knowledge or guess.

The IDL system solves this by:

1. **Script authors** annotate their witness struct with `#[derive(CkbWitness)]` ([`ckb-idl-derive`](https://github.com/OWK50GA/ckb-idl-derive)), which generates an `idl.json` describing the fields.
2. **At deployment**, the deployer appends `sha256(idl.json)` to the code cell data, creating an on-chain commitment.
3. **At spend time**, a client library ([`ckb-idl-client`](https://github.com/OWK50GA/ckb-idl-client)) verifies the local IDL matches the commitment, then structurally validates the proposed witness before submitting the transaction.

This catches malformed witness encodings client-side — before the VM returns an opaque error code.

---

## Workspace contents

```
.
├── contracts/
│   ├── simple-lock/        # Preimage hash lock (one witness field: bytes)
│   ├── timelock-lock/      # Timelock + secp256k1 lock (three witness fields)
│   └── ckb_sudt_script/    # Standard sUDT type script (no IDL)
├── deployer/               # Off-chain CLI: deploy, create locked cells, spend
│   └── src/
│       ├── main.rs         # Command dispatch
│       ├── config.rs       # .env loader
│       ├── deploy_script.rs # Generic deploy + cell creation
│       ├── spend.rs         # Generic + script-specific spend logic
│       └── bin/keygen.rs   # One-time key + address generator
└── tests/                  # Integration tests using ckb-testtool
    └── src/
        ├── simple_lock_tests.rs
        └── timelock_lock_tests.rs
```

---

## The scripts

### simple-lock

A lock cell that can be spent by anyone who knows the preimage of a blake2b-256 hash stored in the script args.

Witness (one field):
```json
[{ "name": "preimage", "type": "bytes", "required": true }]
```

The script checks: `blake2b_256(witness.preimage) == args`.

### timelock-lock

A lock cell that can only be spent after a given timestamp, by someone who holds the corresponding private key. An optional extra payload with a hash commitment is also supported.

Args layout (65 bytes):
- `[0..33]` — compressed secp256k1 public key
- `[33..65]` — blake2b-256 commitment of expected `extra` payload (all zeros = skip)

Witness (three fields):
```json
[
  { "name": "signature",       "type": "secp256k1_sig", "required": true  },
  { "name": "unlock_after_ms", "type": "uint64",        "required": true  },
  { "name": "extra",           "type": "bytes",         "required": false }
]
```

### ckb_sudt_script

Standard sUDT type script. No IDL — it does not use the witness. Token amounts are stored as 16-byte LE `u128` in cell data.

---

## Deployer CLI

The deployer binary provides seven commands. All read `PRIVATE_KEY`, `TESTNET_ADDRESS`, and `CKB_RPC` from `.env`.

```
deploy-simple-lock
    Deploys the simple-lock binary with IDL commitment appended.
    Outputs: code cell tx hash

create-locked-cell <code_tx_hash> <preimage_hex>
    Creates a cell locked by simple-lock with blake2b_256(preimage) as args.
    Outputs: locked cell tx hash

spend-simple-lock <code_tx_hash> <preimage_hex> <idl_path> <locked_tx_hash>
    Verifies IDL, validates witness, spends the simple-lock cell.

deploy-timelock-lock
    Deploys the timelock-lock binary with IDL commitment appended.
    Outputs: code cell tx hash

create-timelock-cell <code_tx_hash> <pubkey_hex> <commitment_hex|"">
    Creates a cell locked by timelock-lock.
    pubkey_hex: 33-byte compressed secp256k1 pubkey
    commitment_hex: 32-byte blake2b hash of expected extra payload, or "" for no commitment

spend-timelock-lock <code_tx_hash> <signing_key_hex> <unlock_after_ms> <extra_hex|""> <idl_path> <locked_tx_hash>
    Verifies IDL, validates witness, signs the transaction, spends the timelock cell.

deploy-sudt
    Deploys the sUDT type script and mints 1,000,000 tokens to the deployer address.
```

---

## Full round-trip: simple-lock

```bash
# 1. Generate a keypair (once)
cargo run --bin keygen
# → paste PRIVATE_KEY, TESTNET_ADDRESS, CKB_RPC into .env
# → fund the address at https://faucet.nervos.org

# 2. Deploy simple-lock
cargo run --bin deployer -- deploy-simple-lock
# → save the code cell tx hash

# 3. Create a locked cell (preimage = "hello" = 68656c6c6f)
cargo run --bin deployer -- create-locked-cell <code_tx_hash> 68656c6c6f
# → save the locked cell tx hash

# 4. Spend the locked cell
cargo run --bin deployer -- spend-simple-lock \
  <code_tx_hash> \
  68656c6c6f \
  ./simple-lock-idl.deployed.json \
  <locked_tx_hash>
```

Expected output for step 4:
```
code_hash: d300d5a3...
IDL commitment verified — IDL is authentic.
Witness structurally valid. Decoded fields:
  preimage (bytes): Bytes([104, 101, 108, 108, 111])
Spend tx hash: 0xe713e2a5...
Cell spent successfully.
```

---

## Prerequisites

```bash
# RISC-V target for the on-chain contracts
rustup target add riscv64imac-unknown-none-elf

# Clang for C dependencies used by ckb-std
# Ubuntu/Debian:
sudo apt install clang llvm
# macOS:
brew install llvm
```

---

## Building

```bash
# Build all contract binaries
make build
# → places binaries in build/release/

# Build the deployer
cargo build -p deployer
```

---

## Testing

The test suite uses `ckb-testtool` to run the RISC-V contracts in a sandboxed VM locally — no testnet required.

```bash
# Build contracts first
make build

# Run integration tests
cargo test --package tests
```

The tests cover both the PSCT boundary (structural validation only, no VM) and full VM execution paths including every error code.

---

## CI

GitHub Actions runs four jobs on every push and PR:

| Job | Rust version | What it does |
|-----|-------------|--------------|
| `check` | 1.95.0 | `cargo fmt --check`, `cargo check`, `cargo clippy -D warnings` |
| `build-contracts` | 1.95.0 + RISC-V target | `make build`, uploads binaries as artifacts |
| `test` | 1.95.0 | Downloads artifacts, runs `cargo test --package tests` |
| `build-deployer` | 1.95.0 | `cargo build -p deployer` |

---

## External dependencies

Both `ckb-idl-derive` and `ckb-idl-client` are referenced as git dependencies from GitHub. Local `path =` references break CI because the runner only checks out this repository.

```toml
# contracts/simple-lock/Cargo.toml
ckb-idl-derive = { git = "https://github.com/OWK50GA/ckb-idl-derive", branch = "refactor/out-dir" }

# deployer/Cargo.toml and tests/Cargo.toml
ckb-idl-client = { git = "https://github.com/OWK50GA/ckb-idl-client", branch = "feat/verify" }
```

---

## Workspace version notes

Two incompatible CKB version series coexist in this workspace:

| Series | Used by |
|--------|---------|
| `ckb-*` `1.x` | `ckb-testtool 1.1`, `ckb-std 1.1` (tests, contracts) |
| `ckb-*` `0.202.x` | `ckb-sdk 4.x` (deployer) |

They do not conflict because neither series pins `ckb-vm` at a version the other requires. `ckb-sdk 3.x` cannot be used here — it pins `ckb-vm = 0.24.13` while `ckb-testtool 1.1` requires `0.24.14`.

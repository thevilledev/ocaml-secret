# Mirage Crypto adoption proof

`mirage-crypto` 2.4.0 is the reference downstream integration for `secret`.
It is a useful target because its public symmetric-key APIs take `string`, its
AES and ChaCha20 implementations exercise different key-retention behavior,
and the repository can test both cryptographic compatibility and process-memory
residue locally.

The dependency belongs in the application (or in a small application-specific
adapter), not in `mirage-crypto` itself:

```text
application
|- secret
`- mirage-crypto
```

This keeps `mirage-crypto`'s dependency cone unchanged. It also makes the
unsafe boundary visible in the code that owns the key lifetime.

## What the proof establishes

Install `mirage-crypto`, then run the combined functional and memory proof:

```sh
opam install mirage-crypto.2.4.0
SECRET_MIRAGE_CRYPTO=true dune build @mirage-crypto-proof
```

The functional consumer in `test/mirage_crypto_consumer.ml` checks:

- migrated AES-256-GCM output against a NIST test vector and the legacy
  string-key path;
- an AES schedule still works after its raw `Secret.t` has been destroyed,
  demonstrating that the scoped view did not escape key setup;
- exception cleanup and ownership for an invalid AES key; and
- operation-scoped ChaCha20-Poly1305 output against the legacy path.

The memory census in `test/leak_scan.ml` then scans all writable process
mappings. It checks that the zero-copy AES setup introduces no verbatim raw-key
string, while the legacy conversion does. Its dedicated destruction checkpoint
keeps a payload mapped through a test-only retained view, observes the key
before `Secret.destroy`, and observes only zero bytes afterward. See
[the census](census.md) for the measured limits.

This is a compatibility and memory-lifetime proof for the tested versions, not
a cryptographic audit of either library. Re-run it whenever `mirage-crypto`'s
key representation changes.

## Migration path

### 1. Add the dependency

Add `secret` beside the application's existing `mirage-crypto` dependency:

```lisp
(libraries secret secret.unix mirage-crypto)
```

Keep the existing crypto API and ciphertext format. This migration changes key
storage and lifetime, not the wire protocol.

### 2. Move key creation out of heap strings

Prefer a producer that writes directly into secret memory:

```ocaml
let key = Secret.random ~hardened:true 32

let key_from_file path =
  let key = Secret_unix.read_file ~hardened:true path in
  if Secret.length key = 32 then key
  else begin
    Secret.destroy key;
    invalid_arg "AES-256 key file must contain exactly 32 bytes"
  end
```

`Secret.of_string old_key` is useful for an incremental migration, but the old
immutable string remains in the OCaml heap and cannot be wiped. It therefore
does not prove the desired end state.

### 3. Adapt according to whether the crypto key retains its input

AES expands the input into a key schedule. Its raw key only needs to be
borrowed during `of_secret`:

```ocaml
let aes_gcm_key secret =
  Secret.Unsafe.with_string_view secret Mirage_crypto.AES.GCM.of_secret

let raw = key_from_file key_path in
let aes =
  Fun.protect
    ~finally:(fun () -> Secret.destroy raw)
    (fun () -> aes_gcm_key raw)
in
Mirage_crypto.AES.GCM.authenticate_encrypt ~key:aes ~nonce plaintext
```

By contrast, `Mirage_crypto.Chacha20.of_secret` in 2.4.0 returns its input
string as the key. Returning that key from `with_string_view` would let a
scoped view escape. Keep the complete operation inside the borrow instead:

```ocaml
let chacha20_encrypt ~key ~nonce ?adata plaintext =
  Secret.Unsafe.with_string_view key (fun raw ->
      let key = Mirage_crypto.Chacha20.of_secret raw in
      Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ?adata plaintext)
```

Do not generalize the AES wrapper over the `Mirage_crypto.AEAD` signature: that
signature does not specify whether `of_secret` copies or retains its argument.

### 4. Make ownership explicit

The application should own the `Secret.t`, destroy it on rotation and shutdown,
and avoid storing unscoped views. Use `Fun.protect`, `Secret.with_secret`, or
`Secret.with_random` for bounded lifetimes. If hardening is a requirement rather
than best effort, call `Secret.require_hardening` and fail closed.

### 5. Keep the proof in CI

Run `@mirage-crypto-proof` on Linux or macOS with the same `mirage-crypto`
version range used by the application. The ordinary `secret` test suite does
not require `mirage-crypto`; the proof remains an explicit downstream job so a
foundational package is not pulled into every build.

## Security boundary after migration

The migration removes the long-lived raw key from the OCaml heap and gives the
application deterministic destruction of its owner. It does not make
`mirage-crypto`'s derived state secret-aware:

- AES expanded schedules are ordinary OCaml heap values and can survive a
  major collection.
- ChaCha20 constructs working state during each operation; `secret` cannot wipe
  copies made inside the implementation.
- plaintext, ciphertext, nonces, and associated data keep their existing
  representations.
- kernel buffers, registers, the C stack, hibernation, and hostile privileged
  processes remain outside the guarantee.

Eliminating the remaining derived-key residue requires a change in
`mirage-crypto` itself: allocate and explicitly wipe its schedules and working
state, or accept caller-owned secret storage all the way through the primitive.

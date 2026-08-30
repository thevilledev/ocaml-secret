# Leak census

`test/leak_scan.exe` scans writable process mappings for the 24-byte tail of
an AES-256 key. The key originates in `Secret.t`; its payload is excluded from
the counts.

Observed on macOS 26, Apple Silicon, OCaml 5.4.1, and mirage-crypto 2.4.0:

| Case after cleanup | Raw key | Expanded key |
|---|---:|---:|
| Key held only in `Secret.t` | 0 | 0 |
| Retained payload after `Secret.destroy` | 0, all bytes read back as zero | 0 |
| Zero-copy view; schedule died young and minor heap scrubbed | 0 | 0 |
| Zero-copy view; schedule reached the major heap | 0 | 1 |
| Heap-string baseline; schedule reached the major heap | 1 | 1 |

The zero-copy view avoids a raw-key heap copy. It cannot remove key schedules
allocated by the receiving library. A promoted schedule survives
`Gc.full_major`, `Secret.Gc.scrub_minor_heap`, and `Secret.destroy`.

The destruction checkpoint deliberately creates one unscoped view so the
allocation remains mapped and readable after `Secret.destroy`. Before the
call, the census finds the reference key in that payload. After the call, it
finds no key bytes and separately reads every retained payload byte back as
zero. This distinguishes zeroization from a result caused only by freeing or
unmapping the allocation. Production integrations should continue to prefer
scoped views.

Run the census with:

```sh
opam install mirage-crypto.2.4.0
SECRET_CENSUS=true dune build @census
```

Run the functional downstream compatibility checks and this census together
with:

```sh
SECRET_MIRAGE_CRYPTO=true dune build @mirage-crypto-proof
```

The tested application migration, including the different safe patterns for
AES and ChaCha20, is documented in
[the Mirage Crypto adoption proof](mirage-crypto-migration.md).

It is intentionally excluded from the package's normal `with-test`
dependencies because its expectations describe a particular cryptographic
implementation and allocator, not the `Secret` API's functional correctness.

# Leak census

`test/leak_scan.exe` scans writable process mappings for the 24-byte tail of
an AES-256 key. The key originates in `Secret.t`; its payload is excluded from
the counts.

Observed on macOS 26, Apple Silicon, OCaml 5.4.1, and mirage-crypto 2.4.0:

| Case after cleanup | Raw key | Expanded key |
|---|---:|---:|
| Key held only in `Secret.t` | 0 | 0 |
| Zero-copy view; schedule died young and minor heap scrubbed | 0 | 0 |
| Zero-copy view; schedule reached the major heap | 0 | 1 |
| Heap-string baseline; schedule reached the major heap | 1 | 1 |

The zero-copy view avoids a raw-key heap copy. It cannot remove key schedules
allocated by the receiving library. A promoted schedule survives
`Gc.full_major`, `Secret.Gc.scrub_minor_heap`, and `Secret.destroy`.

Run the census with:

```sh
opam install mirage-crypto
SECRET_CENSUS=true dune build @census
```

It is intentionally excluded from the package's normal `with-test`
dependencies because its expectations describe a particular cryptographic
implementation and allocator, not the `Secret` API's functional correctness.

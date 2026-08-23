# secret — secret key material outside the OCaml heap

`Secret.t` owns a fixed-length byte buffer allocated in C memory, outside the
OCaml garbage-collected heap. The bytes are never copied by the GC, are
zeroized deterministically, can be compared in constant time, can optionally
be page-locked and excluded from core dumps, and can be handed to *existing*
`string`/`bytes` APIs through zero-copy views.

```ocaml
let key = Secret.random 32 in                      (* OS entropy, straight into C memory *)
let k   = Mirage_crypto.AES.GCM.of_secret (Secret.Unsafe.string_view key) in
(* ... *)
Secret.destroy key                                 (* zeroized now, not when the GC feels like it *)
```

Status: **0.1.0 — experimental**. OCaml ≥ 4.14 (5.x primary). Linux and
macOS are tested; FreeBSD, Windows (mingw) and MirageOS/solo5 compile with
reduced features. On 4.14 the runtime treats views as foreign pointers in
polymorphic `compare`/`hash`/`Marshal` (`String.equal` and C stubs are
unaffected); see the `Secret.Unsafe` documentation.

## Why

Every key in today's OCaml crypto stack (mirage-crypto, ocaml-tls, kdf, x509,
HACL\*'s bindings) is an immutable heap `string`. The runtime never zeroes
freed memory, copies every small block when it is promoted from the minor
heap, and leaves the old copy behind. A key that was a `string` stays in
process memory for the lifetime of the process. See
[doc/census.md](doc/census.md) for measurements and
[mirage/mirage-crypto#237](https://github.com/mirage/mirage-crypto/issues/237)
for the ecosystem discussion.

## What you get

| Property | How |
|---|---|
| Payload never in the OCaml heap, never moved or duplicated by the GC | custom block → C header → C memory; the handle is a single pointer |
| Deterministic zeroization | `destroy`, GC finalization of the handle, and `at_exit` for everything still alive; `explicit_bzero`/`memset_s`/`SecureZeroMemory` in a separate translation unit |
| Zero-copy interop with `string`/`bytes` APIs | the payload carries a valid OCaml string header outside the heap (`Caml_out_of_heap_header`, the representation the runtime itself uses for static data) — `Secret.Unsafe.string_view` is a real `string`, usable by any C stub calling `String_val` |
| No accidental copies through the language | `compare`/`=` and `Marshal` raise, `Hashtbl.hash` ignores the contents, `pp` prints `<secret:32B>` |
| Constant-time equality | `Secret.equal`, `Secret.equal_string`; verified with a dudect-style harness (`bench/ct_equal.ml`) |
| Hardened tier (opt-in) | guard pages, canary, `mlock`, `MADV_DONTDUMP`/`MADV_NOCORE`/`MAP_CONCEAL`; every feature's outcome is reported by `Secret.status`, never assumed |
| Process-wide hardening | `Secret.Process.harden`: `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `PT_DENY_ATTACH`, optional `mlockall`; `scrub_env` |
| Hygiene for the rest of the heap | `Secret.Gc.scrub_minor_heap` zeroes the free part of the minor heap after a minor collection |
| Memory-safe views | released payload blocks are pooled for other secrets, never returned to `malloc`: a stale view reads zeros or another secret, never unmapped memory |
| Secrets straight from files/descriptors | `Secret_unix.read_fd` / `read_file` bypass the channel buffer and `Unix.read`'s 64 KiB C stack buffer |

## What this does NOT protect against

Be precise about this; the library's documentation is too.

- **Copies you did not make through this library.** Kernel page cache, socket
  buffers, terminal and window-system buffers, `environ`, the PEM text you
  decoded, the DER the ASN.1 parser sliced, the `Z.t` limbs Zarith keeps
  inline in custom blocks (RSA/DSA/DH keys cannot leave the heap).
- **Key-equivalent data built by libraries that take `string` keys.** A key
  schedule expanded into a heap `Bytes` is as good as the key. Until a
  library allocates those in secret memory, `Secret.t` protects one copy of
  several (see the census).
- **C stack and registers.** AES-NI keeps the schedule in `__m128i` locals;
  nothing at this level can erase them. Go needed a runtime primitive
  (`runtime/secret`, Go 1.26) for this.
- **Crashes.** No at-exit handler runs on a signal, `Unix._exit` or a runtime
  fatal error.
- **Swap and hibernation.** `mlock` is page-granular, bounded by
  `RLIMIT_MEMLOCK`, needs `IPC_LOCK` in containers, and suspend-to-disk
  ignores it entirely (mlock(2)).
- **Core dumps on macOS.** There is no per-mapping `MADV_DONTDUMP`; use
  `Secret.Process.harden` (`RLIMIT_CORE=0`).
- **root, ptrace, /proc/pid/mem, cold boot, a compromised kernel or
  hypervisor.** Keys that must survive those belong in an HSM/KMS.
- **MirageOS.** The OS features are no-ops and the only entropy source is the
  in-heap PRNG; what remains is zeroization against snapshots.

## Tiers

- **default** (`Secret.create n`): `calloc` memory, zero on release, pooled
  reuse. ~80 ns per create+destroy. For many small or short-lived keys.
- **hardened** (`Secret.create ~hardened:true n`): its own mapping with guard
  pages and a canary, `mlock`, core-dump exclusion where the OS supports it.
  3 pages of address space and ~2 µs per secret. For a few long-lived keys.

## For library authors

Accepting a secret costs nothing: take the `string` view.

```ocaml
let of_secret_buffer (s : Secret.t) = of_secret (Secret.Unsafe.string_view s)
```

Keeping *your* key material out of the heap: allocate it with `Secret.create`
and keep the owner next to the view.

```ocaml
type key = { rk : string; owner : Secret.t }        (* rk == Secret.Unsafe.string_view owner *)
let expand raw = let owner = Secret.create 240 in
  derive_round_keys raw (Secret.Unsafe.bytes_view owner);
  { rk = Secret.Unsafe.string_view owner; owner }
let wipe k = Secret.destroy k.owner
```

C stubs that want a `Secret.t` directly include `secret.h` (installed):
`Is_secret(v)`, `secret_ptr(v)`, `secret_len(v)`,
`secret_borrow_string_or_secret(v, &p, &len)` (accepts either a string or a
secret), `secret_zeroize`, `secret_ct_equal`.

## Building and testing

```
opam install . --deps-only --with-test
dune build @install @runtest
dune exec bench/ct_equal.exe      # constant-time check, run on bare metal
dune exec bench/alloc_bench.exe
```

The test suite covers GC promotion/compaction, finalization from other
domains, `at_exit` wiping (observed from a child process), fork policies,
`ulimit -l 0`, guard-page and canary death, the C API, and the leak census.

## Relation to other work

- Core OCaml developers recommend exactly this shape — out-of-heap storage
  with explicit release ([discuss.ocaml.org #11071](https://discuss.ocaml.org/t/11071));
  the runtime needs no change.
- Cryptokit wipes in-heap buffers; eqaf compares in constant time; this
  library is the out-of-heap owner both can work with.
- `bytesrw`'s PSA bindings keep keys behind C handles inside TF-PSA-Crypto;
  `Secret.t` is the pure-OCaml-ecosystem complement and can hold material
  imported to or exported from such handles.

## License

ISC.

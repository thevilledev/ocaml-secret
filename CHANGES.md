## 0.1.0 (unreleased)

Initial release.

- `Secret.t`: out-of-heap secret buffers with deterministic zeroization
  (`destroy`, GC finalization, `at_exit`), constant-time `equal`, redacted
  `pp`, no `compare`/`hash`/`Marshal`.
- Zero-copy `string`/`bytes`/bigstring views backed by an out-of-heap OCaml
  string block; released blocks are pooled per size class and never returned
  to the C allocator while a view could exist.
- Hardened tier: guard pages, canary, `mlock`, `MADV_DONTDUMP`/`MADV_NOCORE`/
  `MAP_CONCEAL`, `MADV_WIPEONFORK`; outcome reported through `status`.
- `Secret.Scratch` (major-heap scratch buffers), `Secret.Gc.scrub_minor_heap`,
  `Secret.Process.harden`/`scrub_env`, fork policies, entropy fallback hook.
- `secret.unix`: `read_fd`/`read_file`/`write_fd` directly on secret memory.
- Public C header `secret.h` for stubs.
- Leak census and dudect-style constant-time harness.

Known limitations: no page-backed tier on Windows yet (`VirtualAlloc`/
`VirtualLock` planned); no core-dump exclusion on macOS; MirageOS/solo5 has
the default tier only and needs `set_entropy_source`.

# Changes

## 0.1.2 (2026-09-02)

- Remove the upper bound on the OCaml version. It excluded every release
  from 5.6 onwards without a known incompatibility, which is what
  opam-repository asks packages not to do.

Otherwise documentation only: the README gained the header diagram. No
library code changed from 0.1.1.

## 0.1.1 (2026-09-01)

- Build on the whole declared dune range. 0.1.0 required dune 3.24 even
  though it depends on `dune >= 3.8`: dune before 3.15 rejects a `select`
  target that is also named in `modules`, and older dune expands
  `%{exe:...}` to a bare basename, which the tests then failed to resolve.
- Require `dune-configurator` 3.8 or later; it previously had no lower
  bound.
- Run the exit-time zeroization tests on Windows.

The library itself is unchanged: `src/` and `unix/` are identical to 0.1.0,
and this release fixes only packaging metadata and the test suite.

## 0.1.0 (2026-09-01)

- Add out-of-heap secret buffers with explicit destruction, finalization, and
  exit-time zeroization.
- Add constant-time equality, redacted printing, and controlled views.
- Add optional guard pages, canaries, page locking, dump exclusion, and fork
  policies with per-value status reporting.
- Add scratch buffers, minor-heap scrubbing, process hardening, and direct Unix
  file-descriptor I/O.
- Keep owners alive for scoped views and permanently retain destroyed unscoped
  view storage so it can never expose a later secret. Retained and pooled
  blocks stay reachable, so leak checkers report them as reachable memory,
  and `parked_count` reports how many blocks are permanently retained.
- Define concurrent reads as supported while requiring caller synchronization
  for mutation, destruction, process-wide wiping, and blocking I/O.
- Install `secret.h` for C consumers.
- Add an executable Mirage Crypto adoption proof covering AES and ChaCha20
  migration semantics, known-answer compatibility, and process-memory residue.

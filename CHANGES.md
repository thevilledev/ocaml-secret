# Changes

## 0.1.0 (2026-08-30)

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

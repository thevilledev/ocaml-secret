# Changes

## 0.1.0 (2026-08-24)

- Add out-of-heap secret buffers with explicit destruction, finalization, and
  exit-time zeroization.
- Add constant-time equality, redacted printing, and controlled views.
- Add optional guard pages, canaries, page locking, dump exclusion, and fork
  policies with per-value status reporting.
- Add scratch buffers, minor-heap scrubbing, process hardening, and direct Unix
  file-descriptor I/O.
- Install `secret.h` for C consumers.

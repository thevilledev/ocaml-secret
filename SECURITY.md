# Security policy

`secret` is experimental pre-1.0 software and has not received an independent
security audit. Treat its memory-hardening features as defense in depth, not as
a replacement for process isolation or hardware-backed key storage.

## Supported versions

Until 1.0, security fixes are provided for the latest released version and the
`main` branch only. Older pre-1.0 releases may require upgrading rather than a
backport.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Email
`ville@vesilehto.fi` with the subject `[ocaml-secret security]` and include:

- the affected version or commit;
- the operating system, architecture, and OCaml version;
- the relevant threat model and security impact;
- a minimal reproducer or enough detail to confirm the issue; and
- whether the report or its details have been shared elsewhere.

You should receive an acknowledgement within seven days. Remediation and
disclosure timing will be coordinated after the report is reproduced and its
impact is understood. Please allow a reasonable remediation window before
public disclosure.

For non-sensitive correctness bugs and feature requests, use the public issue
tracker.

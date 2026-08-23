(lang dune 3.8)
(name secret)
(version 0.1.0)
(generate_opam_files true)

(source (github thevilledev/ocaml-secret))
(license ISC)
(authors "Ville Vesilehto <ville@vesilehto.fi>")
(maintainers "Ville Vesilehto <ville@vesilehto.fi>")
(documentation "https://thevilledev.github.io/ocaml-secret/")

(package
 (name secret)
 (synopsis
  "Secret key material outside the OCaml heap: zeroized, lockable, constant-time equality")
 (description
  "Secret.t owns a fixed-length byte buffer allocated in C memory, outside the OCaml
garbage-collected heap. The bytes are never copied by minor-to-major promotion or compaction,
are zeroized on explicit destruction, on garbage collection of the handle and at normal program
exit, can optionally be page-backed with guard pages, mlock and core-dump exclusion, and can be
handed to existing string-based APIs through zero-copy views. The library documents precisely
what it does and does not protect against.")
 (tags (security cryptography memory org:mirage))
 (depends
  (ocaml (>= 4.14.0))
  (dune (>= 3.8))
  dune-configurator
  (alcotest (and :with-test (>= 1.7.0)))
  (mirage-crypto (and :with-test (>= 2.0.0)))))

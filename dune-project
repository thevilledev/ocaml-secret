(lang dune 3.8)
(name secret)
(version 0.1.1)
(generate_opam_files true)

(source (github thevilledev/ocaml-secret))
(documentation https://ville.dev/ocaml-secret/)
(license ISC)
(authors "Ville Vesilehto <ville@vesilehto.fi>")
(maintainers "Ville Vesilehto <ville@vesilehto.fi>")
(package
 (name secret)
 (synopsis
  "Zeroized secret memory outside the OCaml heap")
 (description
  "Secret.t stores fixed-length data outside the OCaml heap. It supports explicit
zeroization, constant-time equality, optional page hardening, and zero-copy views.
This experimental pre-1.0 implementation has not received an independent security audit.")
 (tags (security cryptography memory))
 (depends
  (ocaml (and (>= 4.14.0) (< 5.6)))
  (dune-configurator (>= 3.8))
  (alcotest (and :with-test (>= 1.7.0)))))

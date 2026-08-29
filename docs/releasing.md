# Releasing to OPAM

The first public release should be cut only after the normal CI and scheduled
portability workflow are green. The release commit must contain the intended
version in `dune-project`, the generated `secret.opam`, and a dated entry in
`CHANGES.md`.

From a clean checkout, run:

```sh
dune build @fmt
opam lint --strict secret.opam
opam install . --deps-only --with-test --with-doc
dune build @install @runtest @doc
```

Then test the exact tracked source that will become the release archive:

```sh
archive_dir=$(mktemp -d)
git archive --format=tar HEAD | tar -xf - -C "$archive_dir"
cd "$archive_dir"
opam install . --with-test --with-doc
```

Create a signed `v<version>` tag, push it, and wait for tag CI. Publish a GitHub
release for that tag, then prepare the OPAM repository submission with
`opam-publish`. Inspect the generated source URL and checksum before submitting
the pull request to `ocaml/opam-repository`.

Do not reuse or move a published tag: OPAM source checksums make release
archives immutable.

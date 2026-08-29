# Releasing to OPAM

Publication is a separate maintainer action after the preparation PRs are
reviewed and merged. Do not tag or publish from a feature branch.

## 1. Prepare the release commit

Start from a clean, up-to-date `main`. Confirm that the package name is still
unclaimed; this command must report no matching package:

```sh
opam update
opam show secret
```

Replace `unreleased` in `CHANGES.md` with the actual publication date. Confirm
that `dune-project` and generated `secret.opam` both say `0.1.0`, then commit
that date-only release change.

## 2. Validate the exact commit

Run both GitHub workflows manually. All required CI, Linux, macOS, musl, and
i386 jobs must pass; inspect the best-effort Windows and solo5 results. Run the
local release checks from a clean checkout:

```sh
dune build secret.opam
git diff --exit-code -- secret.opam
dune build @fmt
opam lint --strict secret.opam
opam install . --deps-only --with-test --with-doc
dune build @install @runtest @doc
```

Test the exact tracked source independently of working-tree files:

```sh
secret_archive_dir=$(mktemp -d)
git archive --format=tar HEAD | tar -xf - -C "$secret_archive_dir"
cd "$secret_archive_dir"
opam install . --with-test --with-doc
```

## 3. Sign and publish the release

Only after the reviewed commit passes every required check, create and push a
signed annotated tag:

```sh
git tag -s -a v0.1.0 -m "secret 0.1.0"
git push origin v0.1.0
```

Wait for both tag-triggered workflows. Then create a release from the existing
verified tag; `--verify-tag` prevents GitHub CLI from silently creating one:

```sh
gh release create v0.1.0 --verify-tag --title "secret 0.1.0" --notes-from-tag
```

Download the immutable tag archive and record both hashes used for review:

```sh
curl --fail --location \
  --output secret-0.1.0.tar.gz \
  https://github.com/thevilledev/ocaml-secret/archive/refs/tags/v0.1.0.tar.gz
openssl dgst -sha256 secret-0.1.0.tar.gz
openssl dgst -sha512 secret-0.1.0.tar.gz
```

Preview the OPAM repository change before submitting it:

```sh
opam-publish --tag=v0.1.0 --dry-run
opam-publish --tag=v0.1.0
```

Inspect the submitted source URL, SHA256, SHA512, compiler bounds, dependencies,
and build instructions in the `ocaml/opam-repository` PR. Do not reuse, move,
or replace the tag or archive after publication.

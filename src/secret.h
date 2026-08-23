/* secret.h -- public C interface of the OCaml `secret` library.

   Include this from the C stubs of a library that wants to accept a
   `Secret.t` directly (instead of, or in addition to, a string view).

   A Secret.t is a custom block whose payload lives outside the OCaml heap.
   secret_ptr() returns the payload pointer (NULL once destroyed); the pointer
   stays valid and stable as long as the Secret.t value is reachable and has
   not been destroyed. Never retain the pointer across an OCaml allocation
   that could make the Secret.t unreachable. */

#ifndef SECRET_H
#define SECRET_H

#include <stddef.h>
#include <caml/mlvalues.h>
#include <caml/custom.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECRET_IDENTIFIER "secret.t.v1"

/* The custom operations of Secret.t (never registered; only used for
   identification and finalization). */
extern struct custom_operations secret_custom_ops;

#define Is_secret(v)                                                    \
  (Is_block(v) && Tag_val(v) == Custom_tag &&                           \
   Custom_ops_val(v) == &secret_custom_ops)

enum {
  SECRET_OK = 0,
  SECRET_DESTROYED = -1,
  SECRET_NOT_A_SECRET = -2
};

/* Payload pointer, or NULL if [v] was destroyed (or is not a secret). */
const unsigned char *secret_ptr(value v);
unsigned char *secret_ptr_mut(value v);

/* Logical length in bytes. Valid even after destruction. 0 if not a secret. */
size_t secret_len(value v);

/* 1 if destroyed (or not a secret), 0 otherwise. */
int secret_is_destroyed(value v);

/* Borrow the payload of a Secret.t. Returns SECRET_OK, SECRET_DESTROYED or
   SECRET_NOT_A_SECRET. */
int secret_borrow(value v, const unsigned char **p, size_t *len);

/* Same, but also accepts an ordinary OCaml string (String_tag block). This
   lets one stub serve both `string` and `Secret.t` arguments. */
int secret_borrow_string_or_secret(value v, const unsigned char **p,
                                   size_t *len);

/* Zeroize [n] bytes at [p] with a primitive the compiler cannot elide
   (explicit_bzero / memset_explicit / memset_s / SecureZeroMemory /
   volatile fallback). */
void secret_zeroize(void *p, size_t n);

/* Constant-time equality of two buffers of the same length [n]: returns 1 if
   equal, 0 otherwise. The running time depends on [n] only. */
int secret_ct_equal(const unsigned char *a, const unsigned char *b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* SECRET_H */

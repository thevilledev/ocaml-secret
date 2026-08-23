/* secret_ct.c -- constant-time equality, in its own translation unit.

   The running time depends on the length only. The result is derived
   arithmetically from the OR-accumulated XOR of all byte pairs; there is no
   data-dependent branch. Validate on a new platform/compiler with the
   dudect-style harness in bench/ct_equal.ml rather than assuming. */

#include <stddef.h>
#include "secret.h"

int secret_ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
  volatile unsigned int d = 0;
  size_t i;
  for (i = 0; i < n; i++) d |= (unsigned int) (a[i] ^ b[i]);
  /* d in [0,255]; (d - 1) >> 8 is 1 iff d == 0 (unsigned wrap). */
  return (int) (1u & (((unsigned int) d - 1u) >> 8));
}

/* Test helpers: observe wipes, corrupt memory on purpose. Not installed. */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>

#include "secret.h"

typedef void (*secret_release_hook_fn)(const unsigned char *, size_t, uint32_t);
extern void secret_set_release_hook(secret_release_hook_fn f);

/* Reuse-pool size-class mapping (secret_alloc.c). */
extern size_t secret_pool_slot(size_t bsz);
extern size_t secret_block_size_of(size_t len);

CAMLprim value helper_block_size(value vlen)
{
  return Val_long((long) secret_block_size_of((size_t) Long_val(vlen)));
}

CAMLprim value helper_pool_slot(value vlen)
{
  size_t bsz = secret_block_size_of((size_t) Long_val(vlen));
  return Val_long((long) secret_pool_slot(bsz));
}

static long hook_calls = 0, hook_nonzero = 0;
static int hook_print = 0;

static void hook(const unsigned char *payload, size_t len, uint32_t flags)
{
  size_t i;
  int nonzero = 0;
  (void) flags;
  for (i = 0; i < len; i++)
    if (payload[i] != 0) { nonzero = 1; break; }
  hook_calls++;
  if (nonzero) hook_nonzero++;
  if (hook_print) {
    char line[64];
    int n = snprintf(line, sizeof line, "wiped %lu %s\n", (unsigned long) len,
                     nonzero ? "nonzero" : "zero");
    if (n > 0) { ssize_t r = write(1, line, (size_t) n); (void) r; }
  }
}

CAMLprim value helper_install_hook(value vprint)
{
  hook_print = Bool_val(vprint);
  hook_calls = hook_nonzero = 0;
  secret_set_release_hook(hook);
  return Val_unit;
}

CAMLprim value helper_hook_calls(value unit)
{
  (void) unit;
  return Val_long(hook_calls);
}

CAMLprim value helper_hook_nonzero(value unit)
{
  (void) unit;
  return Val_long(hook_nonzero);
}

/* Write one byte at payload + offset (may be negative or out of bounds:
   used to hit guard pages and the canary). */
CAMLprim value helper_poke(value v, value voff)
{
  unsigned char *p = secret_ptr_mut(v);
  long off = Long_val(voff);
  if (p == NULL) return Val_false;
  p[off] = 0xAA;
  return Val_true;
}

/* Read one byte at payload + offset. */
CAMLprim value helper_peek(value v, value voff)
{
  const unsigned char *p = secret_ptr(v);
  long off = Long_val(voff);
  if (p == NULL) return Val_long(-1);
  return Val_long(p[off]);
}

/* The C-level contract: Is_secret / secret_borrow_string_or_secret. */
CAMLprim value helper_borrow_len(value v)
{
  const unsigned char *p;
  size_t len;
  int r = secret_borrow_string_or_secret(v, &p, &len);
  if (r != SECRET_OK) return Val_long(r);
  return Val_long((long) len);
}

CAMLprim value helper_is_secret(value v)
{
  return Val_bool(Is_secret(v));
}

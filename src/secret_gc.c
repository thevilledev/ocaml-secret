/* secret_gc.c -- scrub the calling domain's minor heap.

   After caml_minor_collection() every live young object has been promoted
   and the domain's allocation pointer is reset to the end of the minor heap
   (runtime/minor_gc.c). Everything below young_ptr is free memory that still
   holds the bytes of every object that died young -- handshake transients,
   KDF intermediates, Bytes.create scratch -- so zeroing it removes those
   copies. Only the calling domain's heap is touched. This relies on the
   documented invariant young_start <= young_ptr <= young_end
   (runtime/caml/domain_state.tbl). */

#include "secret_internal.h"

#include <caml/memory.h>
#include <caml/minor_gc.h>
#include <caml/domain_state.h>

CAMLprim value secret_ml_scrub_minor_heap(value unit)
{
  char *start, *ptr;
  (void) unit;
  caml_minor_collection();
#if OCAML_VERSION >= 50000
  start = (char *) Caml_state_field(young_start);
#else
  start = (char *) Caml_state_field(young_alloc_start);
#endif
  ptr = (char *) Caml_state_field(young_ptr);
  if (ptr > start) secret_zeroize(start, (size_t) (ptr - start));
  return Val_unit;
}

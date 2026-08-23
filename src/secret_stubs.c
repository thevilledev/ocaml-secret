/* secret_stubs.c -- Secret.t custom block, registry, lifecycle and accessors. */

#include "secret_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/custom.h>
#include <caml/bigarray.h>
#include <caml/address_class.h>

#if defined(SECRET_HAVE_PTHREAD_ATFORK)
#include <pthread.h>
#endif

/* ---- registry -------------------------------------------------------------- */

static struct secret_hdr registry_head;
static _Atomic int registry_lock_word = 0;
static size_t live_count = 0;
static int registry_initialised = 0;

void secret_registry_lock(void)
{
  for (;;) {
    int expected = 0;
    if (atomic_compare_exchange_weak_explicit(&registry_lock_word, &expected, 1,
                                              memory_order_acquire,
                                              memory_order_relaxed))
      return;
  }
}

void secret_registry_unlock(void)
{
  atomic_store_explicit(&registry_lock_word, 0, memory_order_release);
}

static void registry_init(void)
{
  if (!registry_initialised) {
    registry_head.prev = &registry_head;
    registry_head.next = &registry_head;
    registry_initialised = 1;
  }
}

static void registry_link(struct secret_hdr *h)
{
  secret_registry_lock();
  registry_init();
  h->next = registry_head.next;
  h->prev = &registry_head;
  registry_head.next->prev = h;
  registry_head.next = h;
  live_count++;
  /* Allocation happens outside this lock. Reapply the current policy here so
     a concurrent set_fork_policy cannot leave a just-created mapping with the
     previous advice. */
  (void) secret_mem_set_wipeonfork(h, secret_get_fork_policy());
  secret_registry_unlock();
}

static void registry_unlink(struct secret_hdr *h)
{
  secret_registry_lock();
  if (h->prev != NULL && h->next != NULL) {
    h->prev->next = h->next;
    h->next->prev = h->prev;
    h->prev = h->next = NULL;
    live_count--;
  }
  secret_registry_unlock();
}

/* ---- test hook ------------------------------------------------------------------ */

/* Undocumented: called after every zeroization with the (now zero) payload.
   Used by the test suite to observe finalizer/at-exit wipes. */
static secret_release_hook_fn release_hook = NULL;

void secret_set_release_hook(secret_release_hook_fn f) { release_hook = f; }

/* ---- payload lifecycle ------------------------------------------------------ */

/* Zeroize the payload and, if [release], hand the block back to the pool/OS.
   Idempotent and safe from any thread or domain (ownership is decided by the
   atomic exchange on [ptr]). Must not be called with the registry lock held
   when [release] is set. */
static void destroy_payload(struct secret_hdr *h, int release)
{
  uintptr_t p;
  unsigned char *payload;
  uint32_t f;
  /* Normal destruction serializes the ownership exchange with registry-wide
     operations that inspect the mapping. wipe_all and atfork already hold
     the registry lock and request deferred release. */
  if (release) secret_registry_lock();
  p = atomic_exchange(&h->ptr, (uintptr_t) 0);
  if (release) secret_registry_unlock();
  if (p == 0) return;
  payload = (unsigned char *) p;
  f = atomic_load(&h->flags);
  if (f & SF_CANARY) {
    uint64_t c;
    memcpy(&c, payload - 16, sizeof c);
    if (c != h->canary)
      caml_fatal_error("Secret: memory corruption detected (canary mismatch)");
  }
  /* everything but the padding byte, so a stale view keeps a valid length */
  secret_zeroize(payload, h->bsz - 1);
  atomic_store(&h->flags, f | SF_DESTROYED);
  if (release_hook != NULL) release_hook(payload, h->len, f);
  if (release) {
    secret_mem_release(h, payload);
  } else {
    /* wipe_all permits other domains to finish an in-flight access. Keep the
       zeroed storage valid until the owning handle can be finalized, but do
       not lose the pointer needed to release it then. The registry lock
       serializes this store with finalization; the atfork child is single
       threaded. */
    h->retired = payload;
  }
}

static void secret_finalize(value v)
{
  struct secret_hdr *h = Secret_hdr_val(v);
  unsigned char *retired;
  if (h == NULL) return;
  destroy_payload(h, 1);
  registry_unlink(h);
  retired = h->retired;
  if (retired != NULL) secret_mem_release(h, retired);
  free(h);
  Secret_hdr_val(v) = NULL;
}

struct custom_operations secret_custom_ops = {
  SECRET_IDENTIFIER,
  secret_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default
};

/* ---- public C API (secret.h) ------------------------------------------------- */

static inline struct secret_hdr *hdr_of(value v)
{
  if (!Is_secret(v)) return NULL;
  return Secret_hdr_val(v);
}

const unsigned char *secret_ptr(value v)
{
  struct secret_hdr *h = hdr_of(v);
  if (h == NULL) return NULL;
  return (const unsigned char *) atomic_load(&h->ptr);
}

unsigned char *secret_ptr_mut(value v)
{
  struct secret_hdr *h = hdr_of(v);
  if (h == NULL) return NULL;
  return (unsigned char *) atomic_load(&h->ptr);
}

size_t secret_len(value v)
{
  struct secret_hdr *h = hdr_of(v);
  return h == NULL ? 0 : h->len;
}

int secret_is_destroyed(value v)
{
  struct secret_hdr *h = hdr_of(v);
  return h == NULL || atomic_load(&h->ptr) == 0;
}

int secret_borrow(value v, const unsigned char **p, size_t *len)
{
  struct secret_hdr *h = hdr_of(v);
  uintptr_t q;
  if (h == NULL) return SECRET_NOT_A_SECRET;
  q = atomic_load(&h->ptr);
  if (q == 0) return SECRET_DESTROYED;
  *p = (const unsigned char *) q;
  *len = h->len;
  return SECRET_OK;
}

int secret_borrow_string_or_secret(value v, const unsigned char **p, size_t *len)
{
  if (Is_block(v) && Tag_val(v) == String_tag) {
    *p = (const unsigned char *) String_val(v);
    *len = caml_string_length(v);
    return SECRET_OK;
  }
  return secret_borrow(v, p, len);
}

/* ---- static empty string (returned by views of destroyed secrets) ------------ */

static struct {
  header_t hd;
  unsigned char data[8];
} empty_block = { 0, { 0, 0, 0, 0, 0, 0, 0, 7 } };

static value empty_string_value(void)
{
  if (empty_block.hd == 0) empty_block.hd = secret_string_header(1);
  return (value) empty_block.data;
}

/* ---- OCaml stubs ------------------------------------------------------------- */

#define Hdr(v) ((struct secret_hdr *) Secret_hdr_val(v))

static inline unsigned char *live_payload(struct secret_hdr *h)
{
  return h == NULL ? NULL : (unsigned char *) atomic_load(&h->ptr);
}

CAMLprim value secret_ml_create(value vlen, value vflags)
{
  CAMLparam2(vlen, vflags);
  CAMLlocal1(v);
  size_t len = (size_t) Long_val(vlen);
  uint32_t req = (uint32_t) Long_val(vflags);
  struct secret_hdr *h = (struct secret_hdr *) calloc(1, sizeof *h);
  size_t mem;
  if (h == NULL) caml_raise_out_of_memory();
  if (secret_mem_alloc(h, len, req) != 0) {
    free(h);
    caml_raise_out_of_memory();
  }
  mem = sizeof *h + h->raw_size;
  v = caml_alloc_custom_mem(&secret_custom_ops, sizeof(struct secret_hdr *), mem);
  Secret_hdr_val(v) = h;
  registry_link(h);
  CAMLreturn(v);
}

CAMLprim value secret_ml_destroy(value v)
{
  struct secret_hdr *h = Hdr(v);
  if (h != NULL) destroy_payload(h, 1);
  return Val_unit;
}

CAMLprim value secret_ml_length(value v)
{
  struct secret_hdr *h = Hdr(v);
  return Val_long(h == NULL ? 0 : (long) h->len);
}

CAMLprim value secret_ml_is_destroyed(value v)
{
  struct secret_hdr *h = Hdr(v);
  return Val_bool(h == NULL || atomic_load(&h->ptr) == 0);
}

#define SF_LOCK_LOST_SYNTH (1u << 12)

CAMLprim value secret_ml_status(value v)
{
  struct secret_hdr *h = Hdr(v);
  uint32_t f;
  if (h == NULL) return Val_long(SF_DESTROYED);
  f = atomic_load(&h->flags);
  if (atomic_load(&h->ptr) == 0) f |= SF_DESTROYED;
  if ((f & SF_PAGE_BACKED) && (f & SF_LOCKED) &&
      h->fork_gen != secret_fork_generation_now())
    f |= SF_LOCK_LOST_SYNTH;
  return Val_long((long) f);
}

CAMLprim value secret_ml_lock_errno(value v)
{
  struct secret_hdr *h = Hdr(v);
  return Val_long(h == NULL ? 0 : h->lock_errno);
}

CAMLprim value secret_ml_fill(value v, value vc)
{
  struct secret_hdr *h = Hdr(v);
  unsigned char *p = live_payload(h);
  if (p == NULL) return Val_long(-1);
  memset(p, Int_val(vc), h->len);
  return Val_long(0);
}

CAMLprim value secret_ml_zero(value v)
{
  struct secret_hdr *h = Hdr(v);
  unsigned char *p = live_payload(h);
  if (p == NULL) return Val_long(-1);
  secret_zeroize(p, h->len);
  return Val_long(0);
}

/* blit src[soff..soff+len) -> dst[doff..doff+len); returns 0, -1 destroyed,
   -2 out of bounds */
CAMLprim value secret_ml_blit(value vsrc, value vsoff, value vdst, value vdoff,
                              value vlen)
{
  struct secret_hdr *hs = Hdr(vsrc), *hd = Hdr(vdst);
  unsigned char *ps = live_payload(hs), *pd = live_payload(hd);
  size_t soff = (size_t) Long_val(vsoff), doff = (size_t) Long_val(vdoff);
  size_t len = (size_t) Long_val(vlen);
  if (ps == NULL || pd == NULL) return Val_long(-1);
  if (Long_val(vsoff) < 0 || Long_val(vdoff) < 0 || Long_val(vlen) < 0 ||
      soff > hs->len || len > hs->len - soff ||
      doff > hd->len || len > hd->len - doff)
    return Val_long(-2);
  memmove(pd + doff, ps + soff, len);
  return Val_long(0);
}

CAMLprim value secret_ml_blit_from_string(value vs, value vsoff, value vdst,
                                          value vdoff, value vlen)
{
  struct secret_hdr *hd = Hdr(vdst);
  unsigned char *pd = live_payload(hd);
  size_t slen = caml_string_length(vs);
  size_t soff = (size_t) Long_val(vsoff), doff = (size_t) Long_val(vdoff);
  size_t len = (size_t) Long_val(vlen);
  if (pd == NULL) return Val_long(-1);
  if (Long_val(vsoff) < 0 || Long_val(vdoff) < 0 || Long_val(vlen) < 0 ||
      soff > slen || len > slen - soff || doff > hd->len || len > hd->len - doff)
    return Val_long(-2);
  memmove(pd + doff, String_val(vs) + soff, len);
  return Val_long(0);
}

CAMLprim value secret_ml_blit_to_bytes(value vsrc, value vsoff, value vb,
                                       value vdoff, value vlen)
{
  struct secret_hdr *hs = Hdr(vsrc);
  unsigned char *ps = live_payload(hs);
  size_t blen = caml_string_length(vb);
  size_t soff = (size_t) Long_val(vsoff), doff = (size_t) Long_val(vdoff);
  size_t len = (size_t) Long_val(vlen);
  if (ps == NULL) return Val_long(-1);
  if (Long_val(vsoff) < 0 || Long_val(vdoff) < 0 || Long_val(vlen) < 0 ||
      soff > hs->len || len > hs->len - soff || doff > blen || len > blen - doff)
    return Val_long(-2);
  memmove(Bytes_val(vb) + doff, ps + soff, len);
  return Val_long(0);
}

/* 1 equal, 0 different, 2 destroyed */
CAMLprim value secret_ml_equal(value va, value vb)
{
  struct secret_hdr *ha = Hdr(va), *hb = Hdr(vb);
  unsigned char *pa = live_payload(ha), *pb = live_payload(hb);
  if (pa == NULL || pb == NULL) return Val_long(2);
  if (ha->len != hb->len) return Val_long(0);
  return Val_long(secret_ct_equal(pa, pb, ha->len));
}

CAMLprim value secret_ml_equal_string(value va, value vs)
{
  struct secret_hdr *ha = Hdr(va);
  unsigned char *pa = live_payload(ha);
  if (pa == NULL) return Val_long(2);
  if (ha->len != caml_string_length(vs)) return Val_long(0);
  return Val_long(secret_ct_equal(pa, (const unsigned char *) String_val(vs),
                                  ha->len));
}

/* Zero-copy view as an OCaml string/bytes. The caller has checked that the
   secret is alive; if it is not, a static empty string is returned. */
CAMLprim value secret_ml_view(value v)
{
  struct secret_hdr *h = Hdr(v);
  unsigned char *p = live_payload(h);
  if (p == NULL) return empty_string_value();
  atomic_fetch_or(&h->flags, SF_VIEWED);
  return (value) p;
}

/* A scoped view relies on its OCaml callback not retaining the value. It does
   not force the allocation to remain mapped forever after destruction. */
CAMLprim value secret_ml_scoped_view(value v)
{
  struct secret_hdr *h = Hdr(v);
  unsigned char *p = live_payload(h);
  return p == NULL ? empty_string_value() : (value) p;
}

CAMLprim value secret_ml_fill_random(value v)
{
  struct secret_hdr *h = Hdr(v);
  unsigned char *p = live_payload(h);
  if (p == NULL) return Val_long(-2);
  return Val_long(secret_os_random(p, h->len));
}

/* A fresh, zero-filled bytes allocated directly in the major heap. */
CAMLprim value secret_ml_alloc_major_bytes(value vlen)
{
  mlsize_t len = (mlsize_t) Long_val(vlen);
  mlsize_t wosize = (len + sizeof(value)) / sizeof(value);
  mlsize_t bsz = wosize * sizeof(value);
  value r = caml_alloc_shr(wosize, String_tag);
  memset(Bytes_val(r), 0, bsz);
  Byte(r, bsz - 1) = (char) (bsz - 1 - len);
  return caml_check_urgent_gc(r);
}

CAMLprim value secret_ml_wipe_bytes(value vb)
{
  secret_zeroize(Bytes_val(vb), caml_string_length(vb));
  return Val_unit;
}

CAMLprim value secret_ml_is_young(value v)
{
  return Val_bool(Is_block(v) && Is_young(v));
}

/* ---- process-wide ---------------------------------------------------------- */

CAMLprim value secret_ml_wipe_all(value unit)
{
  struct secret_hdr *h;
  (void) unit;
  secret_registry_lock();
  registry_init();
  for (h = registry_head.next; h != &registry_head; h = h->next)
    destroy_payload(h, 0);
  secret_registry_unlock();
  return Val_unit;
}

CAMLprim value secret_ml_live_count(value unit)
{
  size_t n;
  (void) unit;
  secret_registry_lock();
  n = live_count;
  secret_registry_unlock();
  return Val_long((long) n);
}

CAMLprim value secret_ml_pool_count(value unit)
{
  (void) unit;
  return Val_long((long) secret_pool_count());
}

CAMLprim value secret_ml_capabilities(value unit)
{
  (void) unit;
  return Val_long((long) secret_capabilities());
}

CAMLprim value secret_ml_page_size(value unit)
{
  (void) unit;
  return Val_long((long) secret_page_size());
}

CAMLprim value secret_ml_zeroize_name(value unit)
{
  (void) unit;
  return caml_copy_string(secret_zeroize_name());
}

/* ---- fork ------------------------------------------------------------------ */

#if defined(SECRET_HAVE_PTHREAD_ATFORK)
static void atfork_prepare(void)
{
  /* Fork only after registry and pool mutations have reached a consistent
     state. The lock is inherited by the forking thread into the child. */
  secret_registry_lock();
}

static void atfork_parent(void)
{
  secret_registry_unlock();
}

static void atfork_child(void)
{
  struct secret_hdr *h;
  secret_bump_fork_generation();
  if (secret_get_fork_policy()) {
    for (h = registry_head.next; h != &registry_head; h = h->next) {
      uintptr_t p = atomic_exchange(&h->ptr, (uintptr_t) 0);
      if (p != 0) {
        secret_zeroize((void *) p, h->bsz - 1);
        h->retired = (unsigned char *) p;
        atomic_fetch_or(&h->flags, SF_DESTROYED | SF_FORK_WIPED);
      }
    }
  }
  secret_registry_unlock();
}
#endif

static int initialised = 0;

CAMLprim value secret_ml_init(value unit)
{
  (void) unit;
  if (!initialised) {
    initialised = 1;
    secret_registry_lock();
    registry_init();
    secret_registry_unlock();
    (void) empty_string_value();
#if defined(SECRET_HAVE_PTHREAD_ATFORK)
    (void) pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
#endif
  }
  return Val_unit;
}

CAMLprim value secret_ml_set_fork_policy(value vwipe)
{
  struct secret_hdr *h;
  int wipe = Bool_val(vwipe);
  secret_registry_lock();
  registry_init();
  secret_set_fork_policy(wipe);
  for (h = registry_head.next; h != &registry_head; h = h->next)
    (void) secret_mem_set_wipeonfork(h, wipe);
  secret_registry_unlock();
  return Val_unit;
}

CAMLprim value secret_ml_after_fork(value unit)
{
  struct secret_hdr *h;
  (void) unit;
  secret_registry_lock();
  registry_init();
  for (h = registry_head.next; h != &registry_head; h = h->next)
    (void) secret_mem_relock(h);
  secret_registry_unlock();
  return Val_unit;
}

/* ---- bigarray views ---------------------------------------------------------- */

static unsigned char revoked_sentinel[16];

CAMLprim value secret_ml_bigstring_view(value v)
{
  CAMLparam1(v);
  CAMLlocal1(ba);
  struct secret_hdr *h = Hdr(v);
  unsigned char *p = live_payload(h);
  intnat dim = p == NULL ? 0 : (intnat) h->len;
  ba = caml_ba_alloc_dims(CAML_BA_UINT8 | CAML_BA_C_LAYOUT | CAML_BA_EXTERNAL, 1,
                          p == NULL ? revoked_sentinel : p, dim);
  CAMLreturn(ba);
}

CAMLprim value secret_ml_revoke_bigstring(value ba)
{
  struct caml_ba_array *b = Caml_ba_array_val(ba);
  b->data = revoked_sentinel;
  b->dim[0] = 0;
  return Val_unit;
}

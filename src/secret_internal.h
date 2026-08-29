/* Internal definitions shared by the C translation units of `secret`.
   Not installed. */

#ifndef SECRET_INTERNAL_H
#define SECRET_INTERNAL_H

#include "secret_platform.h"

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

/* Use the caml_-prefixed runtime namespace and unprefixed domain-state
   fields on 4.x; no-op on 5.x. */
#ifndef CAML_NAME_SPACE
#define CAML_NAME_SPACE
#endif

#include <caml/version.h>
#if OCAML_VERSION < 50000
/* Make_header / Caml_black live behind CAML_INTERNALS on 4.x. */
#define CAML_INTERNALS
#endif
#include <caml/mlvalues.h>
#include <caml/gc.h>

#include "secret.h"

/* ---- flags ------------------------------------------------------------- */

#define SF_HARDENED_REQ      (1u << 0)  /* caller asked for the hardened tier */
#define SF_PAGE_BACKED       (1u << 1)  /* payload lives in its own mapping */
#define SF_GUARDED           (1u << 2)  /* guard pages around the payload */
#define SF_CANARY            (1u << 3)  /* canary before the OCaml header */
#define SF_LOCKED            (1u << 4)  /* mlock/VirtualLock succeeded */
#define SF_NODUMP            (1u << 5)  /* excluded from core dumps */
#define SF_WIPEONFORK        (1u << 6)  /* MADV_WIPEONFORK applied */
#define SF_DESTROYED         (1u << 7)
#define SF_FORK_WIPED        (1u << 8)  /* wiped by the atfork child handler */
#define SF_VIEWED            (1u << 9)  /* an unscoped view was handed out */
#define SF_LOCK_UNSUPPORTED  (1u << 10) /* platform cannot lock pages */
#define SF_NODUMP_UNSUPPORTED (1u << 11)

/* Unviewed payload blocks up to this size may be pooled for reuse. Viewed
   blocks are permanently parked instead, and larger unviewed blocks are
   released. */
#define SECRET_POOL_MAX_BSZ   (64 * 1024)

/* Bound cached, unowned memory from ordinary create/destroy traffic. Viewed
   blocks are outside this bound because their storage is never reused. This
   limit applies independently to each allocation tier. */
#define SECRET_POOL_MAX_COUNT 64
#define SECRET_POOL_MAX_PER_CLASS 8

/* Bytes between the allocation base and the OCaml header in tier (a):
   [link/pad 8][header 8][payload]. */
#define SECRET_PREFIX_BYTES   16

/* ---- the per-secret header (C memory, never moves) --------------------- */

struct secret_hdr {
  _Atomic(uintptr_t) ptr;      /* payload pointer; 0 <=> destroyed */
  unsigned char *retired;      /* swept by wipe_all/atfork; release at finalize */
  unsigned char *raw;          /* base of the allocation or mapping */
  size_t raw_size;             /* size of the allocation or mapping */
  size_t len;                  /* logical length */
  size_t bsz;                  /* OCaml string block size (multiple of 8) */
  _Atomic(uint32_t) flags;     /* SF_* */
  int32_t lock_errno;          /* errno of a failed lock attempt */
  uint32_t fork_gen;           /* fork generation at lock time */
  uint64_t canary;             /* expected canary (tier b) */
  struct secret_hdr *prev, *next; /* registry links */
};

#define Secret_hdr_val(v) (*(struct secret_hdr **) Data_custom_val(v))

/* ---- helpers implemented in secret_alloc.c ----------------------------- */

/* Page size, or 0 when unknown/unsupported. */
size_t secret_page_size(void);

/* Allocate the payload for [h] (len already set). Returns 0 on success, -1
   on out-of-memory. Sets h->ptr, raw, raw_size, bsz, flags, lock_errno. The
   payload is zero-filled and carries a valid OCaml string header. */
int secret_mem_alloc(struct secret_hdr *h, size_t len, uint32_t req_flags);

/* Return the (already zeroized) payload of [h] to the pool or the OS. Must not
   be called with the registry lock held. */
void secret_mem_release(struct secret_hdr *h, unsigned char *payload);

/* Re-establish page locking after fork. Returns 0/-1. */
int secret_mem_relock(struct secret_hdr *h);

/* Apply or revoke MADV_WIPEONFORK for one live page-backed secret. The caller
   must hold the registry lock so destruction cannot unmap the payload. */
int secret_mem_set_wipeonfork(struct secret_hdr *h, int wipe);

/* Unlock pages (used by the at-exit drain and release). */
void secret_mem_unlock(struct secret_hdr *h);

/* Process-wide capability bitmask (CAP_* below). */
uint32_t secret_capabilities(void);
#define CAP_HARDENED_TIER   (1u << 0)
#define CAP_CAN_LOCK        (1u << 1)
#define CAP_CAN_NODUMP      (1u << 2)
#define CAP_CAN_WIPEONFORK  (1u << 3)
#define CAP_OS_RANDOM       (1u << 4)
#define CAP_ATFORK          (1u << 5)
#define CAP_PROCESS_NOCORE  (1u << 6)
#define CAP_PROCESS_NODUMP  (1u << 7)
#define CAP_PROCESS_LOCKALL (1u << 8)
#define CAP_PROCESS_DENYATTACH (1u << 9)

const char *secret_zeroize_name(void);

/* Fork policy and generation (secret_alloc.c). */
void secret_set_fork_policy(int wipe);
int secret_get_fork_policy(void);
void secret_bump_fork_generation(void);
uint32_t secret_fork_generation_now(void);
size_t secret_pool_count(void);

/* Reuse-pool size-class mapping. Exposed (not installed) so the test suite can
   check that distinct block sizes never share a slot. */
size_t secret_pool_slot(size_t bsz);
size_t secret_block_size_of(size_t len);

/* ---- secret_random.c ----------------------------------------------------- */

/* Fill [n] bytes with OS entropy. Returns 0 on success, -1 when no OS source
   exists on this platform, or a positive errno. */
int secret_os_random(unsigned char *buf, size_t n);

/* ---- secret_stubs.c ---------------------------------------------------- */

typedef void (*secret_release_hook_fn)(const unsigned char *payload, size_t len,
                                       uint32_t flags);
void secret_set_release_hook(secret_release_hook_fn f);

/* Registry lock; exported for secret_process.c / fork handling. */
void secret_registry_lock(void);
void secret_registry_unlock(void);

/* OCaml string block header for an out-of-heap block. */
static inline header_t secret_string_header(mlsize_t wosize)
{
#if OCAML_VERSION >= 50000
  return Caml_out_of_heap_header(wosize, String_tag);
#else
  return Make_header(wosize, String_tag, Caml_black);
#endif
}

/* Block size in bytes for a logical length: exactly the size
   caml_alloc_string would use (a multiple of sizeof(value)), so that a view
   is indistinguishable from an ordinary string (caml_string_equal compares
   wosize first). */
static inline size_t secret_block_size(size_t len)
{
  size_t wosize = (len + sizeof(value)) / sizeof(value);
  return wosize * sizeof(value);
}

/* Write the OCaml header and padding for a payload of logical length [len]
   inside a block of [bsz] bytes whose payload starts at [payload]. */
static inline void secret_format_block(unsigned char *payload, size_t len,
                                       size_t bsz)
{
  header_t *hp = (header_t *) (payload - sizeof(header_t));
  *hp = secret_string_header((mlsize_t) (bsz / sizeof(value)));
  /* bytes [len, bsz-1) are zero, last byte is the padding count */
  payload[bsz - 1] = (unsigned char) (bsz - 1 - len);
}

#endif /* SECRET_INTERNAL_H */

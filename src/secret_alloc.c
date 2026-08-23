/* secret_alloc.c -- payload allocation: tier (a) calloc, tier (b) page-backed.

   Layouts (bsz is a multiple of 8, exactly the block size of an OCaml
   string of the same length):

     tier (a):  [link/pad 8][OCaml header 8][payload bsz]
                raw = payload - 16, raw_size = 16 + bsz

     tier (b):  [guard page][ ... pad ... [canary 8][OCaml header 8][payload bsz]][guard page]
                raw = mapping base, raw_size = page + inner + page,
                inner = round_up(16 + bsz, page), payload = raw + page + inner - bsz

   Released payload blocks are zero and keep a valid OCaml string header. They
   are pooled per size class and reused only for other secrets, so a stale
   view (a `string` handed out by Secret.Unsafe) can never point to unmapped
   or foreign memory. Unviewed blocks larger than SECRET_POOL_MAX_BSZ are
   returned to the OS. */

#include "secret_internal.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if !defined(SECRET_CONFIG_FREESTANDING) && !defined(_WIN32)
#include <unistd.h>
#if defined(SECRET_HAVE_MMAP)
#include <sys/mman.h>
#endif
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

/* ---- fork policy (read by tier b for MADV_WIPEONFORK) ------------------ */

static _Atomic int secret_fork_policy_wipe = 0;
static _Atomic uint32_t secret_fork_generation = 0;

void secret_set_fork_policy(int wipe) { atomic_store(&secret_fork_policy_wipe, wipe); }
int secret_get_fork_policy(void) { return atomic_load(&secret_fork_policy_wipe); }
void secret_bump_fork_generation(void) { atomic_fetch_add(&secret_fork_generation, 1); }
uint32_t secret_fork_generation_now(void) { return atomic_load(&secret_fork_generation); }

/* ---- page size ------------------------------------------------------------ */

size_t secret_page_size(void)
{
  static size_t cached = 0;
  if (cached) return cached;
#if defined(SECRET_CONFIG_FREESTANDING)
  cached = 0;
#elif defined(_WIN32)
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  cached = (size_t) si.dwPageSize;
#else
  long p = sysconf(_SC_PAGESIZE);
  cached = p > 0 ? (size_t) p : 4096;
#endif
  return cached;
}

/* ---- canary ---------------------------------------------------------------- */

static uint64_t canary_value = 0;

static uint64_t secret_canary_value(void)
{
  if (canary_value == 0) {
    uint64_t c = 0;
    if (secret_os_random((unsigned char *) &c, sizeof c) != 0 || c == 0) {
      /* no entropy: derive something address-dependent; the canary is an
         overflow detector, not a security boundary */
      uintptr_t a = (uintptr_t) &canary_value;
      c = 0x9e3779b97f4a7c15ULL ^ ((uint64_t) a * 0xbf58476d1ce4e5b9ULL);
      if (c == 0) c = 1;
    }
    /* make sure the canary never contains a NUL byte so C string functions
       cannot be used to read past it silently; cheap and conventional */
    c |= 0x0101010101010101ULL;
    canary_value = c;
  }
  return canary_value;
}

/* ---- pools ----------------------------------------------------------------- */

#define POOL_SLOTS (SECRET_POOL_MAX_BSZ / 8 + 1)
static unsigned char *pool_a[POOL_SLOTS];
static unsigned char *pool_b[POOL_SLOTS];
static size_t pool_a_slot_counts[POOL_SLOTS];
static size_t pool_b_slot_counts[POOL_SLOTS];
static size_t pool_a_count = 0, pool_b_count = 0;

#define Link_slot(payload) ((unsigned char **) ((payload) - 16))

static unsigned char *pool_pop(unsigned char **pool, size_t *slot_counts,
                               size_t *count, size_t bsz)
{
  size_t idx = bsz / 8;
  unsigned char *p = NULL;
  if (idx < POOL_SLOTS) {
    secret_registry_lock();
    p = pool[idx];
    if (p) {
      pool[idx] = *Link_slot(p);
      slot_counts[idx]--;
      (*count)--;
    }
    secret_registry_unlock();
  }
  if (p) *Link_slot(p) = NULL;
  return p;
}

static int pool_push(unsigned char **pool, size_t *slot_counts, size_t *count,
                     size_t bsz, unsigned char *payload)
{
  size_t idx = bsz / 8;
  int inserted = 0;
  /* caller guarantees idx < POOL_SLOTS */
  secret_registry_lock();
  if (*count < SECRET_POOL_MAX_COUNT &&
      slot_counts[idx] < SECRET_POOL_MAX_PER_CLASS) {
    *Link_slot(payload) = pool[idx];
    pool[idx] = payload;
    slot_counts[idx]++;
    (*count)++;
    inserted = 1;
  }
  secret_registry_unlock();
  return inserted;
}

size_t secret_pool_count(void)
{
  size_t count;
  secret_registry_lock();
  count = pool_a_count + pool_b_count;
  secret_registry_unlock();
  return count;
}

/* A block that is too large for the pool but has been viewed must stay
   mapped forever; we keep such blocks on a separate "parking" list so the
   memory stays valid (zeroized). They are never reused. */
static void park_forever(unsigned char *payload)
{
  (void) payload; /* intentionally leaked: stays mapped and zero */
}

/* ---- tier (a) ------------------------------------------------------------ */

static int tier_a_alloc(struct secret_hdr *h, uint32_t req_flags)
{
  size_t bsz = h->bsz;
  unsigned char *payload = NULL;
  unsigned char *raw;

  if (bsz <= SECRET_POOL_MAX_BSZ)
    payload = pool_pop(pool_a, pool_a_slot_counts, &pool_a_count, bsz);
  if (payload == NULL) {
    raw = (unsigned char *) calloc(1, SECRET_PREFIX_BYTES + bsz);
    if (raw == NULL) return -1;
    payload = raw + SECRET_PREFIX_BYTES;
  } else {
    raw = payload - SECRET_PREFIX_BYTES;
  }
  secret_format_block(payload, h->len, bsz);
  h->raw = raw;
  h->raw_size = SECRET_PREFIX_BYTES + bsz;
  h->lock_errno = 0;
  h->fork_gen = secret_fork_generation_now();
  atomic_store(&h->flags, (req_flags & SF_HARDENED_REQ));
  atomic_store(&h->ptr, (uintptr_t) payload);
  return 0;
}

static void tier_a_release(struct secret_hdr *h, unsigned char *payload, int viewed)
{
  size_t bsz = h->bsz;
  if (bsz <= SECRET_POOL_MAX_BSZ &&
      pool_push(pool_a, pool_a_slot_counts, &pool_a_count, bsz, payload)) {
    return;
  }
  if (viewed) {
    park_forever(payload);
  } else {
    free(payload - SECRET_PREFIX_BYTES);
  }
}

/* ---- tier (b) ------------------------------------------------------------ */

#if defined(SECRET_HAVE_MMAP) && !defined(SECRET_CONFIG_FREESTANDING) && !defined(_WIN32)
#define SECRET_TIER_B 1
#else
#define SECRET_TIER_B 0
#endif

#if SECRET_TIER_B

static size_t round_up(size_t n, size_t m) { return (n + m - 1) / m * m; }

static void tier_b_geometry(size_t bsz, size_t page, size_t *inner, size_t *map_size)
{
  *inner = round_up(16 + bsz, page);
  *map_size = page + *inner + page;
}

static void tier_b_apply_advice(struct secret_hdr *h, unsigned char *inner_base,
                                size_t inner)
{
  uint32_t f = atomic_load(&h->flags);
#if defined(SECRET_HAVE_MLOCK)
  if (mlock(inner_base, inner) == 0) {
    f |= SF_LOCKED;
    h->lock_errno = 0;
  } else {
    h->lock_errno = errno;
  }
#else
  f |= SF_LOCK_UNSUPPORTED;
#endif
#if defined(SECRET_HAVE_MADV_DONTDUMP)
  if (madvise(inner_base, inner, MADV_DONTDUMP) == 0) f |= SF_NODUMP;
#elif defined(SECRET_HAVE_MADV_NOCORE)
  if (madvise(inner_base, inner, MADV_NOCORE) == 0) f |= SF_NODUMP;
#elif defined(SECRET_HAVE_MAP_CONCEAL)
  f |= SF_NODUMP; /* MAP_CONCEAL was passed to mmap */
#else
  f |= SF_NODUMP_UNSUPPORTED;
#endif
#if defined(SECRET_HAVE_MADV_WIPEONFORK) && defined(SECRET_HAVE_MADV_KEEPONFORK)
  if (secret_get_fork_policy()) {
    if (madvise(inner_base, inner, MADV_WIPEONFORK) == 0) f |= SF_WIPEONFORK;
  } else if (madvise(inner_base, inner, MADV_KEEPONFORK) == 0) {
    f &= ~SF_WIPEONFORK;
  }
#endif
  h->fork_gen = secret_fork_generation_now();
  atomic_store(&h->flags, f);
}

static int tier_b_alloc(struct secret_hdr *h, uint32_t req_flags)
{
  size_t page = secret_page_size();
  size_t bsz = h->bsz, inner, map_size;
  unsigned char *payload = NULL, *raw;
  uint32_t f = req_flags & SF_HARDENED_REQ;

  if (page == 0) return -1;
  tier_b_geometry(bsz, page, &inner, &map_size);

  if (bsz <= SECRET_POOL_MAX_BSZ)
    payload = pool_pop(pool_b, pool_b_slot_counts, &pool_b_count, bsz);
  if (payload != NULL) {
    raw = payload + bsz - inner - page;
    f |= SF_PAGE_BACKED | SF_GUARDED;
  } else {
    int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(SECRET_HAVE_MAP_CONCEAL)
    mflags |= MAP_CONCEAL;
#endif
    void *m = mmap(NULL, map_size, PROT_READ | PROT_WRITE, mflags, -1, 0);
    if (m == MAP_FAILED) return -1;
    raw = (unsigned char *) m;
    f |= SF_PAGE_BACKED;
    if (mprotect(raw, page, PROT_NONE) == 0 &&
        mprotect(raw + page + inner, page, PROT_NONE) == 0)
      f |= SF_GUARDED;
    payload = raw + page + inner - bsz;
  }

  /* canary just before the OCaml header */
  *(uint64_t *) (payload - 16) = secret_canary_value();
  f |= SF_CANARY;
  secret_format_block(payload, h->len, bsz);

  h->raw = raw;
  h->raw_size = map_size;
  h->canary = secret_canary_value();
  h->lock_errno = 0;
  atomic_store(&h->flags, f);
  tier_b_apply_advice(h, raw + page, inner);
  atomic_store(&h->ptr, (uintptr_t) payload);
  return 0;
}

static void tier_b_release(struct secret_hdr *h, unsigned char *payload, int viewed)
{
  size_t page = secret_page_size();
  size_t bsz = h->bsz, inner, map_size;
  tier_b_geometry(bsz, page, &inner, &map_size);
  secret_mem_unlock(h);
  if (bsz <= SECRET_POOL_MAX_BSZ &&
      pool_push(pool_b, pool_b_slot_counts, &pool_b_count, bsz, payload)) {
    return;
  }
  if (viewed) {
    park_forever(payload);
  } else {
    munmap(h->raw, map_size);
  }
}

#endif /* SECRET_TIER_B */

/* ---- public (internal) entry points ---------------------------------------- */

int secret_mem_alloc(struct secret_hdr *h, size_t len, uint32_t req_flags)
{
  int fallback_errno = 0;
  uint32_t extra = 0;
  h->len = len;
  h->bsz = secret_block_size(len);
  if (req_flags & SF_HARDENED_REQ) {
#if SECRET_TIER_B
    if (tier_b_alloc(h, req_flags) == 0) return 0;
    fallback_errno = errno ? errno : ENOMEM;
    /* fall back to tier (a); status reports page_backed = false and the
       mmap error as the lock failure */
#else
    extra = SF_LOCK_UNSUPPORTED | SF_NODUMP_UNSUPPORTED;
#endif
  }
  if (tier_a_alloc(h, req_flags) != 0) return -1;
  h->lock_errno = fallback_errno;
  if (extra) atomic_fetch_or(&h->flags, extra);
  return 0;
}

void secret_mem_release(struct secret_hdr *h, unsigned char *payload)
{
  uint32_t f = atomic_load(&h->flags);
  int viewed = (f & SF_VIEWED) != 0;
#if SECRET_TIER_B
  if (f & SF_PAGE_BACKED) {
    tier_b_release(h, payload, viewed);
    return;
  }
#endif
  tier_a_release(h, payload, viewed);
}

void secret_mem_unlock(struct secret_hdr *h)
{
#if SECRET_TIER_B && defined(SECRET_HAVE_MLOCK)
  uint32_t f = atomic_load(&h->flags);
  if ((f & SF_PAGE_BACKED) && (f & SF_LOCKED)) {
    size_t page = secret_page_size(), inner, map_size;
    tier_b_geometry(h->bsz, page, &inner, &map_size);
    munlock(h->raw + page, inner);
    atomic_store(&h->flags, f & ~SF_LOCKED);
  }
#else
  (void) h;
#endif
}

int secret_mem_relock(struct secret_hdr *h)
{
#if SECRET_TIER_B && defined(SECRET_HAVE_MLOCK)
  uint32_t f = atomic_load(&h->flags);
  if (!(f & SF_PAGE_BACKED) || atomic_load(&h->ptr) == 0) return 0;
  size_t page = secret_page_size(), inner, map_size;
  tier_b_geometry(h->bsz, page, &inner, &map_size);
  if (mlock(h->raw + page, inner) == 0) {
    h->lock_errno = 0;
    atomic_store(&h->flags, f | SF_LOCKED);
  } else {
    h->lock_errno = errno;
    atomic_store(&h->flags, f & ~SF_LOCKED);
  }
  h->fork_gen = secret_fork_generation_now();
  return 0;
#else
  (void) h;
  return -1;
#endif
}

int secret_mem_set_wipeonfork(struct secret_hdr *h, int wipe)
{
#if SECRET_TIER_B && defined(SECRET_HAVE_MADV_WIPEONFORK) && \
    defined(SECRET_HAVE_MADV_KEEPONFORK)
  uint32_t f = atomic_load(&h->flags);
  size_t page, inner, map_size;
  int advice;
  if (!(f & SF_PAGE_BACKED) || atomic_load(&h->ptr) == 0) return 0;
  page = secret_page_size();
  tier_b_geometry(h->bsz, page, &inner, &map_size);
  advice = wipe ? MADV_WIPEONFORK : MADV_KEEPONFORK;
  if (madvise(h->raw + page, inner, advice) != 0) return -1;
  if (wipe)
    atomic_fetch_or(&h->flags, SF_WIPEONFORK);
  else
    atomic_fetch_and(&h->flags, ~SF_WIPEONFORK);
  return 0;
#else
  (void) h;
  (void) wipe;
  return -1;
#endif
}

uint32_t secret_capabilities(void)
{
  uint32_t c = 0;
#if SECRET_TIER_B
  c |= CAP_HARDENED_TIER;
#if defined(SECRET_HAVE_MLOCK)
  c |= CAP_CAN_LOCK;
#endif
#if defined(SECRET_HAVE_MADV_DONTDUMP) || defined(SECRET_HAVE_MADV_NOCORE) || defined(SECRET_HAVE_MAP_CONCEAL)
  c |= CAP_CAN_NODUMP;
#endif
#if defined(SECRET_HAVE_MADV_WIPEONFORK) && defined(SECRET_HAVE_MADV_KEEPONFORK)
  c |= CAP_CAN_WIPEONFORK;
#endif
#endif
#if defined(SECRET_HAVE_GETRANDOM) || defined(SECRET_HAVE_GETENTROPY) || \
    defined(SECRET_HAVE_ARC4RANDOM_BUF) || defined(SECRET_HAVE_BCRYPTGENRANDOM)
  c |= CAP_OS_RANDOM;
#endif
#if defined(SECRET_HAVE_PTHREAD_ATFORK)
  c |= CAP_ATFORK;
#endif
#if defined(SECRET_HAVE_SETRLIMIT_CORE)
  c |= CAP_PROCESS_NOCORE;
#endif
#if defined(SECRET_HAVE_PRCTL_DUMPABLE)
  c |= CAP_PROCESS_NODUMP;
#endif
#if defined(SECRET_HAVE_MLOCKALL)
  c |= CAP_PROCESS_LOCKALL;
#endif
#if defined(SECRET_HAVE_PT_DENY_ATTACH)
  c |= CAP_PROCESS_DENYATTACH;
#endif
  return c;
}

/* Cycle counter for the constant-time harness. */
#include <stdint.h>
#include <time.h>
#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/alloc.h>

static uint64_t ticks(void)
{
#if defined(__x86_64__) || defined(__i386__)
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t) hi << 32) | lo;
#elif defined(__aarch64__)
  uint64_t v;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
  return v;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
#endif
}

CAMLprim value ct_ticks(value unit)
{
  (void) unit;
  return caml_copy_int64((int64_t) ticks());
}

#include "secret.h"

/* The raw C primitive, bypassing the OCaml wrapper's match on the result. */
CAMLprim value ct_equal_raw(value a, value b)
{
  const unsigned char *pa = secret_ptr(a), *pb = secret_ptr(b);
  size_t la = secret_len(a), lb = secret_len(b);
  if (pa == NULL || pb == NULL || la != lb) return Val_long(-1);
  return Val_long(secret_ct_equal(pa, pb, la));
}

/* In-process memory scanner for the leak census.

   Walks every readable+writable mapping of the current process and counts
   occurrences of a needle. The needle is read from a Secret.t payload (out
   of heap) and never copied into a buffer, so the scanner itself does not
   create hits. Payload ranges of the secrets passed as [exclude] are
   skipped. Hits are classified as: 0 minor heap, 1 stack, 2 other
   (major heap / C heap / anonymous). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CAML_NAME_SPACE
#include <caml/version.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/address_class.h>

#include "secret.h"

#define KIND_MINOR 0
#define KIND_STACK 1
#define KIND_OTHER 2
#define NKINDS 3

struct scan {
  const unsigned char *needle;
  size_t nlen;
  const unsigned char *excl_lo[8], *excl_hi[8];
  int nexcl;
  long hits[NKINDS];
  uintptr_t stack_probe;
};

/* Bytes of the key skipped at the front: a freed major-heap block has its
   first word overwritten by the free-list link, so a verbatim search for the
   whole key would miss stale copies. */
#define SKIP 8

static int excluded(struct scan *s, const unsigned char *p)
{
  int i;
  for (i = 0; i < s->nexcl; i++)
    if (p >= s->excl_lo[i] && p < s->excl_hi[i]) return 1;
  return 0;
}

static int classify(struct scan *s, const unsigned char *p, int region_is_stack)
{
  (void) s;
#if OCAML_VERSION >= 50000
  if ((uintptr_t) p >= caml_minor_heaps_start && (uintptr_t) p < caml_minor_heaps_end)
    return KIND_MINOR;
#else
  if ((char *) p >= (char *) Caml_state_field(young_start) &&
      (char *) p < (char *) Caml_state_field(young_end))
    return KIND_MINOR;
#endif
  if (region_is_stack) return KIND_STACK;
  return KIND_OTHER;
}

static void scan_region(struct scan *s, const unsigned char *base, size_t size,
                        int region_is_stack)
{
  const unsigned char *p = base, *end = base + size;
  unsigned char first;
  if (size < s->nlen || s->nlen == 0) return;
  first = s->needle[0];
  /* the region containing our own stack probe is the stack */
  if (s->stack_probe >= (uintptr_t) base && s->stack_probe < (uintptr_t) end)
    region_is_stack = 1;
  while (p + s->nlen <= end) {
    const unsigned char *q = memchr(p, first, (size_t) (end - p) - s->nlen + 1);
    if (q == NULL) break;
    if (!excluded(s, q) && memcmp(q, s->needle, s->nlen) == 0)
      s->hits[classify(s, q, region_is_stack)]++;
    p = q + 1;
  }
}

#if defined(__APPLE__)

#include <mach/mach.h>
#include <mach/mach_vm.h>

static void scan_all(struct scan *s)
{
  mach_vm_address_t addr = 0;
  for (;;) {
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t) &info, &count, &obj);
    if (kr != KERN_SUCCESS) break;
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
    if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE) &&
        !info.reserved)
      scan_region(s, (const unsigned char *) (uintptr_t) addr, (size_t) size, 0);
    addr += size;
  }
}

#elif defined(__linux__)

static void scan_all(struct scan *s)
{
  FILE *f = fopen("/proc/self/maps", "r");
  char line[512];
  if (f == NULL) return;
  while (fgets(line, sizeof line, f) != NULL) {
    unsigned long lo, hi;
    char perms[8];
    char path[256];
    int n;
    path[0] = 0;
    n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %255s", &lo, &hi, perms, path);
    if (n < 3) continue;
    if (perms[0] != 'r' || perms[1] != 'w') continue;
    if (path[0] == '/' ) continue;                    /* file-backed */
    if (strcmp(path, "[vvar]") == 0 || strcmp(path, "[vsyscall]") == 0) continue;
    scan_region(s, (const unsigned char *) lo, (size_t) (hi - lo),
                strncmp(path, "[stack", 6) == 0);
  }
  fclose(f);
}

#else

static void scan_all(struct scan *s) { (void) s; }

#endif

/* scan(needle, excludes, variant) -> int array of hits per kind.
   variant 0: verbatim tail of the key (bytes SKIP..len);
   variant 1: the same tail with bytes swapped within each 32-bit word (the
   form in which a big-endian-loaded AES key schedule stores the key on a
   little-endian machine). */
CAMLprim value leak_scan(value vneedle, value vexcl, value vvariant)
{
  CAMLparam3(vneedle, vexcl, vvariant);
  CAMLlocal1(res);
  struct scan s;
  int i, n;
  volatile int probe = 0;
  unsigned char swapped[256];
  const unsigned char *full = secret_ptr(vneedle);
  size_t flen = secret_len(vneedle);
  memset(&s, 0, sizeof s);
  s.stack_probe = (uintptr_t) &probe;
  if (full == NULL) caml_failwith("leak_scan: needle destroyed");
  if (flen <= SKIP || flen > sizeof swapped) caml_failwith("leak_scan: needle size");
  /* exclude every listed secret's full payload (and the needle's) */
  s.excl_lo[0] = full;
  s.excl_hi[0] = full + flen;
  s.nexcl = 1;
  n = Wosize_val(vexcl);
  for (i = 0; i < n && s.nexcl < 7; i++) {
    const unsigned char *p = secret_ptr(Field(vexcl, i));
    size_t l = secret_len(Field(vexcl, i));
    if (p != NULL) {
      s.excl_lo[s.nexcl] = p;
      s.excl_hi[s.nexcl] = p + l;
      s.nexcl++;
    }
  }
  if (Int_val(vvariant) == 0) {
    s.needle = full + SKIP;
    s.nlen = flen - SKIP;
  } else {
    size_t k;
    for (k = 0; k + 4 <= flen; k += 4) {
      swapped[k] = full[k + 3]; swapped[k + 1] = full[k + 2];
      swapped[k + 2] = full[k + 1]; swapped[k + 3] = full[k];
    }
    s.needle = swapped + SKIP;
    s.nlen = (flen / 4 * 4) - SKIP;
    s.excl_lo[s.nexcl] = swapped;
    s.excl_hi[s.nexcl] = swapped + sizeof swapped;
    s.nexcl++;
  }
  scan_all(&s);
  secret_zeroize(swapped, sizeof swapped);
  res = caml_alloc(NKINDS, 0);
  for (i = 0; i < NKINDS; i++) Store_field(res, i, Val_long(s.hits[i]));
  CAMLreturn(res);
}

CAMLprim value leak_scan_supported(value unit)
{
  (void) unit;
#if defined(__APPLE__) || defined(__linux__)
  return Val_true;
#else
  return Val_false;
#endif
}

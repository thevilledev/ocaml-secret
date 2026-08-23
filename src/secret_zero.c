/* secret_zero.c -- zeroization that the compiler cannot elide.

   Kept in its own translation unit so that link-time optimisation is the
   only way for a compiler to see across the call. Selection order:
   memset_explicit (C23) > explicit_bzero (glibc 2.25+, musl 1.1.20+, *BSD)
   > explicit_memset (NetBSD) > memset_s (C11 Annex K, macOS)
   > SecureZeroMemory (Windows) > volatile function pointer + barrier. */

#include "secret_platform.h"

#if defined(SECRET_HAVE_MEMSET_S) && !defined(__STDC_WANT_LIB_EXT1__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#if defined(SECRET_HAVE_EXPLICIT_BZERO)
#include <strings.h>
#endif

#include "secret.h"

#if !defined(SECRET_HAVE_MEMSET_EXPLICIT) && !defined(SECRET_HAVE_EXPLICIT_BZERO) && \
    !defined(SECRET_HAVE_EXPLICIT_MEMSET) && !defined(SECRET_HAVE_MEMSET_S) &&      \
    !defined(SECRET_HAVE_SECUREZEROMEMORY)
static void *(*volatile secret_memset_fn)(void *, int, size_t) = memset;
#endif

void secret_zeroize(void *p, size_t n)
{
  if (p == NULL || n == 0) return;
#if defined(SECRET_HAVE_MEMSET_EXPLICIT)
  memset_explicit(p, 0, n);
#elif defined(SECRET_HAVE_EXPLICIT_BZERO)
  explicit_bzero(p, n);
#elif defined(SECRET_HAVE_EXPLICIT_MEMSET)
  explicit_memset(p, 0, n);
#elif defined(SECRET_HAVE_MEMSET_S)
  (void) memset_s(p, n, 0, n);
#elif defined(SECRET_HAVE_SECUREZEROMEMORY)
  SecureZeroMemory(p, n);
#else
  secret_memset_fn(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
#endif
}

const char *secret_zeroize_name(void)
{
#if defined(SECRET_HAVE_MEMSET_EXPLICIT)
  return "memset_explicit";
#elif defined(SECRET_HAVE_EXPLICIT_BZERO)
  return "explicit_bzero";
#elif defined(SECRET_HAVE_EXPLICIT_MEMSET)
  return "explicit_memset";
#elif defined(SECRET_HAVE_MEMSET_S)
  return "memset_s";
#elif defined(SECRET_HAVE_SECUREZEROMEMORY)
  return "SecureZeroMemory";
#else
  return "volatile-memset";
#endif
}

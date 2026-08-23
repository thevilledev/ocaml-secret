/* secret_random.c -- OS entropy written directly into C memory.

   No dependency on the OCaml `unix` library. Returns 0 on success, -1 when
   the platform has no OS entropy source (freestanding/MirageOS), or a
   positive errno value. */

#include "secret_platform.h"

#include <stddef.h>
#include <errno.h>

#if defined(SECRET_CONFIG_FREESTANDING)

int secret_os_random(unsigned char *buf, size_t n)
{
  (void) buf; (void) n;
  return -1;
}

#elif defined(_WIN32)

#include <windows.h>
#include <bcrypt.h>

int secret_os_random(unsigned char *buf, size_t n)
{
#if defined(SECRET_HAVE_BCRYPTGENRANDOM)
  while (n > 0) {
    ULONG chunk = n > 0x7fffffffUL ? 0x7fffffffUL : (ULONG) n;
    NTSTATUS st = BCryptGenRandom(NULL, buf, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) return EIO;
    buf += chunk; n -= chunk;
  }
  return 0;
#else
  (void) buf; (void) n;
  return -1;
#endif
}

#else /* POSIX */

#include <unistd.h>
#include <stdlib.h>
#if defined(SECRET_HAVE_GETRANDOM) || defined(SECRET_HAVE_GETENTROPY)
#include <sys/random.h>
#endif

int secret_os_random(unsigned char *buf, size_t n)
{
#if defined(SECRET_HAVE_GETRANDOM)
  while (n > 0) {
    ssize_t r = getrandom(buf, n, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      return errno ? errno : EIO;
    }
    buf += (size_t) r; n -= (size_t) r;
  }
  return 0;
#elif defined(SECRET_HAVE_GETENTROPY)
  while (n > 0) {
    size_t chunk = n > 256 ? 256 : n;
    if (getentropy(buf, chunk) != 0) return errno ? errno : EIO;
    buf += chunk; n -= chunk;
  }
  return 0;
#elif defined(SECRET_HAVE_ARC4RANDOM_BUF)
  arc4random_buf(buf, n);
  return 0;
#else
  (void) buf; (void) n;
  return -1;
#endif
}

#endif

/* secret_process.c -- process-wide hardening (opt-in, each feature reported). */

#include "secret_internal.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <caml/memory.h>
#include <caml/alloc.h>

#if !defined(SECRET_CONFIG_FREESTANDING) && !defined(_WIN32)
#include <unistd.h>
#if defined(SECRET_HAVE_SETRLIMIT_CORE)
#include <sys/resource.h>
#endif
#if defined(SECRET_HAVE_PRCTL_DUMPABLE)
#include <sys/prctl.h>
#endif
#if defined(SECRET_HAVE_PT_DENY_ATTACH)
#include <sys/types.h>
#include <sys/ptrace.h>
#endif
#if defined(SECRET_HAVE_MLOCKALL)
#include <sys/mman.h>
#endif
extern char **environ;
#endif

/* feature codes (must match secret.ml) */
#define FEAT_NO_CORE_DUMP 0
#define FEAT_NOT_DUMPABLE 1
#define FEAT_LOCK_ALL     2
#define FEAT_DENY_ATTACH  3

/* returns 0 ok, -1 unsupported, errno > 0 failed */
CAMLprim value secret_ml_process_feature(value vfeat)
{
  int feat = Int_val(vfeat);
  int r = -1;
#if defined(SECRET_CONFIG_FREESTANDING) || defined(_WIN32)
  (void) feat;
#else
  switch (feat) {
  case FEAT_NO_CORE_DUMP:
#if defined(SECRET_HAVE_SETRLIMIT_CORE)
    {
      struct rlimit rl;
      rl.rlim_cur = 0;
      rl.rlim_max = 0;
      r = setrlimit(RLIMIT_CORE, &rl) == 0 ? 0 : errno;
    }
#endif
    break;
  case FEAT_NOT_DUMPABLE:
#if defined(SECRET_HAVE_PRCTL_DUMPABLE)
    r = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 ? 0 : errno;
#endif
    break;
  case FEAT_LOCK_ALL:
#if defined(SECRET_HAVE_MLOCKALL)
    r = mlockall(MCL_CURRENT | MCL_FUTURE) == 0 ? 0 : errno;
#endif
    break;
  case FEAT_DENY_ATTACH:
#if defined(SECRET_HAVE_PT_DENY_ATTACH)
    r = ptrace(PT_DENY_ATTACH, 0, 0, 0) == 0 ? 0 : errno;
#endif
    break;
  default:
    break;
  }
#endif
  return Val_long(r);
}

/* Zeroize the value of environment variable [name] in place (the copy held
   in `environ`) and remove it. Returns 1 if found, 0 otherwise, -1 if
   unsupported. */
CAMLprim value secret_ml_scrub_env(value vname)
{
#if defined(SECRET_CONFIG_FREESTANDING) || defined(_WIN32)
  (void) vname;
  return Val_long(-1);
#else
  const char *name = String_val(vname);
  size_t nlen = caml_string_length(vname);
  int found = 0;
  char **e;
  if (environ == NULL || nlen == 0) return Val_long(0);
  for (e = environ; *e != NULL; e++) {
    if (strncmp(*e, name, nlen) == 0 && (*e)[nlen] == '=') {
      char *val = *e + nlen + 1;
      secret_zeroize(val, strlen(val));
      found = 1;
    }
  }
  if (found) unsetenv(name);
  return Val_long(found);
#endif
}

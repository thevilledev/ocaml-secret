/* secret_platform.h -- configuration as seen by the C code.

   Wraps the generated secret_config.h and forces the freestanding profile
   when the target compiler itself says so (MirageOS/solo5 define
   __ocaml_solo5__ / __ocaml_freestanding__), so a configurator run with the
   wrong compiler cannot enable OS features that do not exist there. */

#ifndef SECRET_PLATFORM_H
#define SECRET_PLATFORM_H

#include "secret_config.h"

#if defined(__ocaml_solo5__) || defined(__ocaml_freestanding__)
#ifndef SECRET_CONFIG_FREESTANDING
#define SECRET_CONFIG_FREESTANDING 1
#endif
#undef SECRET_HAVE_MEMSET_EXPLICIT
#undef SECRET_HAVE_EXPLICIT_BZERO
#undef SECRET_HAVE_EXPLICIT_MEMSET
#undef SECRET_HAVE_MEMSET_S
#undef SECRET_HAVE_GETRANDOM
#undef SECRET_HAVE_GETENTROPY
#undef SECRET_HAVE_ARC4RANDOM_BUF
#undef SECRET_HAVE_MMAP
#undef SECRET_HAVE_MLOCK
#undef SECRET_HAVE_MLOCKALL
#undef SECRET_HAVE_MADV_DONTDUMP
#undef SECRET_HAVE_MADV_NOCORE
#undef SECRET_HAVE_MADV_WIPEONFORK
#undef SECRET_HAVE_MAP_CONCEAL
#undef SECRET_HAVE_PTHREAD_ATFORK
#undef SECRET_HAVE_PRCTL_DUMPABLE
#undef SECRET_HAVE_PT_DENY_ATTACH
#undef SECRET_HAVE_SETRLIMIT_CORE
#endif

#endif /* SECRET_PLATFORM_H */

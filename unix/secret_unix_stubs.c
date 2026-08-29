/* read(2)/write(2) directly on secret memory, with the runtime lock
   released. The payload pointer is taken before entering the blocking
   section; destroying the secret concurrently from another thread is a
   programming error (memory stays mapped, so it cannot crash). */

#include <errno.h>
#include <unistd.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>

#include "secret.h"

/* returns bytes read (>= 0) or -1 if destroyed; raises Unix_error */
CAMLprim value secret_unix_read(value vfd, value vsec, value voff, value vlen)
{
  CAMLparam4(vfd, vsec, voff, vlen);
  int fd = Int_val(vfd);
  long off = Long_val(voff), len = Long_val(vlen);
  unsigned char *p = secret_ptr_mut(vsec);
  size_t slen = secret_len(vsec);
  ssize_t r;
  if (p == NULL) CAMLreturn(Val_long(-1));
  if (off < 0 || len < 0 || (size_t) off > slen || (size_t) len > slen - (size_t) off)
    caml_invalid_argument("Secret_unix.read: out of bounds");
  caml_enter_blocking_section();
  do {
    r = read(fd, p + off, (size_t) len);
  } while (r < 0 && errno == EINTR);
  caml_leave_blocking_section();
  if (r < 0) uerror("read", Nothing);
  if (secret_rewipe_if_destroyed(vsec, p)) CAMLreturn(Val_long(-1));
  CAMLreturn(Val_long((long) r));
}

CAMLprim value secret_unix_write(value vfd, value vsec, value voff, value vlen)
{
  CAMLparam4(vfd, vsec, voff, vlen);
  int fd = Int_val(vfd);
  long off = Long_val(voff), len = Long_val(vlen);
  const unsigned char *p = secret_ptr(vsec);
  size_t slen = secret_len(vsec);
  ssize_t r;
  if (p == NULL) CAMLreturn(Val_long(-1));
  if (off < 0 || len < 0 || (size_t) off > slen || (size_t) len > slen - (size_t) off)
    caml_invalid_argument("Secret_unix.write: out of bounds");
  caml_enter_blocking_section();
  do {
    r = write(fd, p + off, (size_t) len);
  } while (r < 0 && errno == EINTR);
  caml_leave_blocking_section();
  if (r < 0) uerror("write", Nothing);
  if (secret_is_destroyed(vsec)) CAMLreturn(Val_long(-1));
  CAMLreturn(Val_long((long) r));
}

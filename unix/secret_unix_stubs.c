/* Read and write directly between an OS descriptor and secret memory, with the
   runtime lock released. The payload pointer is taken before entering the
   blocking section; callers must synchronize mutation, destruction, and
   process-wide wiping. */

#include <errno.h>
#include <limits.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>

#include "secret.h"

#ifdef _WIN32

static intnat secret_win32_read(value vfd, unsigned char *buf, intnat len)
{
  DWORD error = 0;
  DWORD count = 0;

  if (Descr_kind_val(vfd) == KIND_SOCKET) {
    SOCKET socket = Socket_val(vfd);
    int requested = len > INT_MAX ? INT_MAX : (int) len;
    int result;
    caml_enter_blocking_section();
    result = recv(socket, (char *) buf, requested, 0);
    if (result == SOCKET_ERROR)
      error = WSAGetLastError();
    else
      count = (DWORD) result;
    caml_leave_blocking_section();
  } else {
    HANDLE handle = Handle_val(vfd);
    DWORD requested = (uintnat) len > MAXDWORD ? MAXDWORD : (DWORD) len;
    caml_enter_blocking_section();
    if (!ReadFile(handle, buf, requested, &count, NULL))
      error = GetLastError();
    caml_leave_blocking_section();
  }

  if (error != 0) {
    if (error == ERROR_BROKEN_PIPE)
      count = 0;
    else {
      win32_maperr(error);
      uerror("read", Nothing);
    }
  }
  return (intnat) count;
}

static intnat secret_win32_write(value vfd, const unsigned char *buf,
                                 intnat len)
{
  DWORD error = 0;
  DWORD count = 0;

  if (Descr_kind_val(vfd) == KIND_SOCKET) {
    SOCKET socket = Socket_val(vfd);
    int requested = len > INT_MAX ? INT_MAX : (int) len;
    int result;
    caml_enter_blocking_section();
    result = send(socket, (const char *) buf, requested, 0);
    if (result == SOCKET_ERROR)
      error = WSAGetLastError();
    else
      count = (DWORD) result;
    caml_leave_blocking_section();
  } else {
    HANDLE handle = Handle_val(vfd);
    DWORD requested = (uintnat) len > MAXDWORD ? MAXDWORD : (DWORD) len;
    caml_enter_blocking_section();
    if (!WriteFile(handle, buf, requested, &count, NULL))
      error = GetLastError();
    caml_leave_blocking_section();
  }

  if (error != 0) {
    win32_maperr(error);
    uerror("write", Nothing);
  }
  return (intnat) count;
}

#endif

/* returns bytes read (>= 0) or -1 if destroyed; raises Unix_error */
CAMLprim value secret_unix_read(value vfd, value vsec, value voff, value vlen)
{
  CAMLparam4(vfd, vsec, voff, vlen);
  intnat off = Long_val(voff), len = Long_val(vlen);
  unsigned char *p = secret_ptr_mut(vsec);
  size_t slen = secret_len(vsec);
  intnat result;
  if (p == NULL) CAMLreturn(Val_long(-1));
  if (off < 0 || len < 0 || (size_t) off > slen || (size_t) len > slen - (size_t) off)
    caml_invalid_argument("Secret_unix.read: out of bounds");
#ifdef _WIN32
  result = secret_win32_read(vfd, p + (size_t) off, len);
#else
  {
    int fd = Int_val(vfd);
    ssize_t r;
    caml_enter_blocking_section();
    do {
      r = read(fd, p + (size_t) off, (size_t) len);
    } while (r < 0 && errno == EINTR);
    caml_leave_blocking_section();
    if (r < 0) uerror("read", Nothing);
    result = (intnat) r;
  }
#endif
  if (secret_rewipe_if_destroyed(vsec, p)) CAMLreturn(Val_long(-1));
  CAMLreturn(Val_long(result));
}

CAMLprim value secret_unix_write(value vfd, value vsec, value voff, value vlen)
{
  CAMLparam4(vfd, vsec, voff, vlen);
  intnat off = Long_val(voff), len = Long_val(vlen);
  const unsigned char *p = secret_ptr(vsec);
  size_t slen = secret_len(vsec);
  intnat result;
  if (p == NULL) CAMLreturn(Val_long(-1));
  if (off < 0 || len < 0 || (size_t) off > slen || (size_t) len > slen - (size_t) off)
    caml_invalid_argument("Secret_unix.write: out of bounds");
#ifdef _WIN32
  result = secret_win32_write(vfd, p + (size_t) off, len);
#else
  {
    int fd = Int_val(vfd);
    ssize_t r;
    caml_enter_blocking_section();
    do {
      r = write(fd, p + (size_t) off, (size_t) len);
    } while (r < 0 && errno == EINTR);
    caml_leave_blocking_section();
    if (r < 0) uerror("write", Nothing);
    result = (intnat) r;
  }
#endif
  if (secret_is_destroyed(vsec)) CAMLreturn(Val_long(-1));
  CAMLreturn(Val_long(result));
}

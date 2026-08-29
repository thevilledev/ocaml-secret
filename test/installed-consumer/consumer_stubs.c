#define CAML_NAME_SPACE

#include <caml/mlvalues.h>
#include <secret.h>

CAMLprim value consumer_borrowed_length(value secret)
{
  const unsigned char *payload;
  size_t length;
  int result = secret_borrow(secret, &payload, &length);
  (void) payload;
  return result == SECRET_OK ? Val_long((long) length) : Val_long(result);
}

#include <stdlib.h>
#include <string.h>
#include "ed_sigs.h"
#include "crypto_additions.h"

int ed25519_verify(const unsigned char* signature,
                      const unsigned char* ed_pubkey,
                      const unsigned char* msg, const unsigned long msg_len)
{
  unsigned char *verifybuf  = NULL; /* working buffer */
  unsigned char *verifybuf2 = NULL; /* working buffer #2 */
  int result;

  if ((verifybuf = malloc(msg_len + 64)) == 0) {
   result = -1;
   goto err;
  }

  if ((verifybuf2 = malloc(msg_len + 64)) == 0) {
    result = -1;
    goto err;
  }

  memmove(verifybuf, signature, 64);
  memmove(verifybuf+64, msg, msg_len);

  /* Then perform a normal Ed25519 verification, return 0 on success */
  /* The below call has a strange API: */
  /* verifybuf = R || S || message */
  /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets 
     replaced with pubkey for hashing */
  result = crypto_sign_open_modified(verifybuf2, verifybuf, 64 + msg_len, ed_pubkey);

  err:

  if (verifybuf != NULL) {
    free(verifybuf);
  }

  if (verifybuf2 != NULL) {
    free(verifybuf2);
  }

  return result;
}

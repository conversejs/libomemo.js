
#ifndef __ED_SIGS_H__
#define __ED_SIGS_H__

/* returns 0 on success */
int ed25519_verify(const unsigned char* signature, /* 64 bytes */
                      const unsigned char* curve25519_pubkey, /* 32 bytes */
                      const unsigned char* msg, const unsigned long msg_len); /* <= 256 bytes */


#endif

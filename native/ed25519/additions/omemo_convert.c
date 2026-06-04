#include "fe.h"
#include "ge.h"
#include "crypto_additions.h"

/* Curve25519 <-> Ed25519 public key conversions needed by OMEMO 2
   (urn:xmpp:omemo:2), which always transfers the IdentityKey in its Ed25519
   form while this library keeps Curve25519 identity keys internally.

   Both directions reuse the exact field operations used by libomemo-c
   (curve.c: fe_montx_to_edy / fe_edy_to_montx), so the encodings — including
   the forced-zero Edwards sign bit — match the reference implementation that
   real OMEMO 2 clients use. No new cryptography is introduced here. */

/* Convert a 32-byte Curve25519 (Montgomery u-coordinate) public key into the
   corresponding 32-byte Ed25519 (Edwards y-coordinate) public key. fe_tobytes
   leaves the high (sign) bit zero, matching XEdDSA / libomemo-c, which derive
   the published IdentityKey from the public key this way. */
void curve25519_pubkey_to_ed25519_pubkey(unsigned char* ed_pubkey_out, /* 32 bytes */
                                         const unsigned char* curve25519_pubkey /* 32 bytes */)
{
  fe u;
  fe y;

  fe_frombytes(u, curve25519_pubkey);
  fe_montx_to_edy(y, u);
  fe_tobytes(ed_pubkey_out, y);
}

/* Convert a 32-byte Ed25519 public key (Edwards y-coordinate plus sign bit in
   the high bit) into the corresponding 32-byte Curve25519 (Montgomery
   u-coordinate) public key. fe_frombytes ignores the high (sign) bit, and only
   the u-coordinate is used for X25519/DH, so the sign bit is irrelevant. */
void ed25519_pubkey_to_curve25519_pubkey(unsigned char* curve25519_pubkey_out, /* 32 bytes */
                                         const unsigned char* ed_pubkey /* 32 bytes */)
{
  fe y;
  fe u;

  fe_frombytes(y, ed_pubkey);
  fe_edy_to_montx(u, y);
  fe_tobytes(curve25519_pubkey_out, u);
}

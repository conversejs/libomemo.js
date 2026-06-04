# tools

## gen-omemo2-vector.c

One-time generator for the cross-implementation OMEMO 2 interop vector in
`test/omemo2-vector.ts`, used by `test/omemo2.ts`.

It drives [libomemo-c](https://github.com/dino/libomemo-c) — the library Dino
uses — as the omemo:2 *sender* (Alice), then prints Bob's key material and the
ciphertexts as JSON. Those bytes are pasted into `test/omemo2-vector.ts`, pinning
two interop directions with no build dependency at test time:

- **libomemo.js as Bob (decrypt):** decrypts libomemo-c's actual ciphertexts —
  X3DH key exchange, `OMEMOKeyExchange` parsing, the AD/MAC, and the
  Ed25519↔Curve25519 identity-key handling.
- **libomemo.js as Alice (verify):** processes Bob's PreKey bundle, verifying
  libomemo-c's signed-pre-key signature (`bobSignedPreKeySignature`, made over
  the raw 32-byte Montgomery form) against the published Ed25519 identity key
  (`bobIdentityPubEd`).

You only need to re-run this if the wire format or these conventions change.

### Regenerate

Requires `cmake`, `libssl-dev`, `libprotobuf-c-dev`, `protobuf-c-compiler` and a
libomemo-c checkout.

```sh
LC=~/src/libomemo-c

# Build libomemo-c once
( cd "$LC" && mkdir -p build && cd build && cmake .. -DBUILD_SHARED_LIBS=OFF && make -j )

# libomemo-c's test_common.c needs <check.h> for a single macro; stub it.
mkdir -p /tmp/stubinc
printf '#include <stdlib.h>\n#include <stdio.h>\n#define ck_assert_int_eq(a,b) do{long _a=(long)(a),_b=(long)(b); if(_a!=_b){fprintf(stderr,"ck fail %%ld!=%%ld\\n",_a,_b);exit(1);}}while(0)\n' > /tmp/stubinc/check.h

gcc -O2 -w -I/tmp/stubinc -I"$LC/src" -I"$LC/tests" tools/gen-omemo2-vector.c \
    "$LC/tests/test_common.c" "$LC/tests/test_common_openssl.c" \
    "$LC/build/src/libomemo-c.a" -lcrypto -lprotobuf-c -o /tmp/gen-omemo2-vector

/tmp/gen-omemo2-vector   # prints the vector JSON; paste into test/omemo2-vector.ts
```

## dec-omemo2-vector.c

Confirms the **sender direction**: that omemo:2 messages libomemo.js *emits* are
accepted by libomemo-c. The in-repo suite can only round-trip libomemo.js against
itself, so a symmetric off-spec encoding would pass there but fail against a real
peer; this closes that gap.

libomemo-c plays the *receiver* (Bob) and decrypts a key-exchange message that
libomemo.js (Alice) produced. This is a manual, one-time confirmation — there is
no build dependency at test time — re-run it only when the omemo:2 wire format or
the encoder changes.

```sh
# 1. Capture a libomemo.js-produced ciphertext (writes tools/omemo2-sender-vector.txt).
CAPTURE_OMEMO2=1 npx vitest run test/omemo2-sender-capture.test.ts

# 2. Build the decrypter (reuses the libomemo-c build and /tmp/stubinc from above).
gcc -O2 -w -I/tmp/stubinc -I"$LC/src" -I"$LC/tests" tools/dec-omemo2-vector.c \
    "$LC/tests/test_common.c" "$LC/tests/test_common_openssl.c" \
    "$LC/build/src/libomemo-c.a" -lcrypto -lprotobuf-c -o /tmp/dec-omemo2-vector

# 3. Decrypt with libomemo-c; prints "OK: ..." and exits 0 on success.
/tmp/dec-omemo2-vector tools/omemo2-sender-vector.txt
```

Because libomemo.js's encryption is non-deterministic (random base/ephemeral
keys), the captured `tools/omemo2-sender-vector.txt` changes each run; that's
expected — it's a one-shot input, not a pinned golden value.

Last confirmed: 2026-06-09, libomemo-c `master`, decrypting libomemo.js
`omemo-2-support` — `OK` (48-byte plaintext recovered).

import type { PreKeyBundle } from "../src/session/types";
import { hexToArrayBuffer } from "./utils";

/**
 * Cross-implementation interop vector, generated once by libomemo-c (the library
 * Dino uses) acting as the omemo:2 *sender* (Alice). See tools/gen-omemo2-vector.c.
 *
 * It pins both interop directions, with no build dependency at test time:
 *  - libomemo.js plays Bob and decrypts libomemo-c's actual ciphertexts (X3DH
 *    key exchange, OMEMOKeyExchange parsing, the AD/MAC, Ed25519<->Curve handling).
 *  - libomemo.js plays Alice and verifies libomemo-c's signed-pre-key signature
 *    over the raw 32-byte Montgomery form (`bobSignedPreKeySignature`), plus the
 *    published 32-byte Ed25519 identity key (`bobIdentityPubEd`).
 *
 * The reverse sender direction (libomemo-c decrypts libomemo.js's output) is
 * confirmed out-of-band by tools/dec-omemo2-vector.c; see tools/README.md.
 */
export const LIBOMEMO_C_VECTOR = {
    bobRegistrationId: 16004,
    signedPreKeyId: 22,
    preKeyId: 31337,
    bobIdentityPriv: "d87238802956f7320db23e99932d5e6777cba2144ac454cb985a03b2902e557e",
    bobIdentityPub: "05f0ead423fdcd49f328e41ccf0f7b30803f27dab458f7c9b00f78a89ae292c12e",
    bobIdentityPubEd: "e5b399cc3f584632fce457bd4c2f2c4d92460a53295bfbac091f41d2b8f70450",
    bobSignedPreKeyPriv: "9000cc7936814a2f708847fba418f9b432415cb00c5c6ce48b9d93c7cbf2067d",
    bobSignedPreKeyPub: "055c4ee3d55c466985d31dbe428bd151e79ee04ccee4114703d8ce66144e137715",
    bobSignedPreKeySignature:
        "a96f626a938056fa020f5f6fade883036dd5237c532a5db1ce0572854d0dd453f74f784236e1e5afb799504df44bd0c10e9d3b0d578a1349551224b3d3affa02",
    bobPreKeyPriv: "b8485b03104a50425a52c944af31a2a529b6ecd35ffb45d798d30bb7fa8e565b",
    bobPreKeyPub: "058601c15e6cf84a4aa5f8e97e172180c6ebe2aceac4e6e05c58dc3c0c6231912b",
    plaintext1: "6f6d656d6f3a3220696e7465726f7020766563746f72206d657373616765206f6e65",
    ciphertext1:
        "08e9f40110161a208b5e2fc1a8a5c83a4a4a6cddbc85127fb94da3555f4d1431919496753ce5ff5622202e5bc972732be52ab3bc1990af01cabfed25d837c2794eacd18f5fad12788d0b2a6c0a10555c9ecbffda646c0dc9df05fec1d1331258080010001a203647cca04dd5c864ef5f8d2012d8309582edfaa1fe13307ced3add2aeea87d252230bfb8f13be5489ddffe3b8021491ca144f7ca75658cd5a256ebac607ad92f717352e353432321e179269beec10d5e1453",
    plaintext2: "6f6d656d6f3a3220696e7465726f7020766563746f72206d6573736167652074776f",
    ciphertext2:
        "08e9f40110161a208b5e2fc1a8a5c83a4a4a6cddbc85127fb94da3555f4d1431919496753ce5ff5622202e5bc972732be52ab3bc1990af01cabfed25d837c2794eacd18f5fad12788d0b2a6c0a1053d47f3fb009a074954030e3af34bee21258080110001a203647cca04dd5c864ef5f8d2012d8309582edfaa1fe13307ced3add2aeea87d252230d3060852bd08cecc7ccc9ac27b425649af2a52ce12557ed0cb1920cb0debd210acceee9fedbfb40e8e6c9e77308a79f0",
};

/**
 * Bob's omemo:2 PreKey bundle as a real consumer would publish it: identity key
 * in Ed25519 form, signed-pre-key public in the 33-byte 0x05-Curve form. Pass a
 * `signature` to override the (valid) libomemo-c SPK signature, e.g. for a
 * tamper-rejection test.
 */
export function libomemoCBobBundle(
    signature: ArrayBuffer = hexToArrayBuffer(LIBOMEMO_C_VECTOR.bobSignedPreKeySignature)
): PreKeyBundle {
    const v = LIBOMEMO_C_VECTOR;
    return {
        identityKey: hexToArrayBuffer(v.bobIdentityPubEd),
        registrationId: v.bobRegistrationId,
        preKey: { keyId: v.preKeyId, publicKey: hexToArrayBuffer(v.bobPreKeyPub) },
        signedPreKey: {
            keyId: v.signedPreKeyId,
            publicKey: hexToArrayBuffer(v.bobSignedPreKeyPub),
            signature,
        },
    };
}

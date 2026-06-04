/*
 * One-time generator for the cross-implementation OMEMO 2 (urn:xmpp:omemo:2)
 * interop test vector in test/testvectors.ts.
 *
 * It drives libomemo-c (the library Dino uses) as the *sender* (Alice): it
 * builds Bob's omemo:2 PreKey bundle, has Alice establish a session and encrypt
 * two messages, and prints Bob's key material + the ciphertexts as JSON. The
 * captured bytes validate our implementation against libomemo-c, with no build
 * dependency at test time, in two directions:
 *   - libomemo.js plays Bob and decrypts the exact ciphertexts.
 *   - libomemo.js plays Alice and verifies Bob's bundle: the signed-pre-key
 *     signature (bobSignedPreKeySignature, over the raw 32-byte Montgomery form)
 *     and the published Ed25519 identity key (bobIdentityPubEd).
 *
 * Build (against a libomemo-c checkout built with cmake):
 *   LC=~/src/libomemo-c
 *   gcc -O2 -I"$LC/src" -I"$LC/tests" tools/gen-omemo2-vector.c \
 *       "$LC/tests/test_common.c" "$LC/tests/test_common_openssl.c" \
 *       "$LC/build/src/libomemo-c.a" -lcrypto -lprotobuf-c -o /tmp/gen-omemo2-vector
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <protobuf-c/protobuf-c.h>
#include "../src/signal_protocol.h"
#include "session_cipher.h"
#include "session_builder.h"
#include "session_pre_key.h"
#include "curve.h"
#include "ratchet.h"
#include "protocol.h"
#include "test_common.h"

/* Serialises an identity public key in its 32-byte Ed25519 form (the form
   omemo:2 publishes in a PreKey bundle). Defined in libomemo-c's curve.c but
   not exported in curve.h, so forward-declare it here. */
extern int ec_public_key_serialize_protobuf_ed(ProtobufCBinaryData *buffer, const ec_public_key *key);

static signal_context *global_context;

static signal_protocol_address alice_address = { "alice@example.org", 17, 1 };
static signal_protocol_address bob_address = { "bob@example.org", 15, 1 };

static void print_hex_field(const char *name, const uint8_t *data, size_t len, int comma) {
    printf("  \"%s\": \"", name);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\"%s\n", comma ? "," : "");
}

static void dump_buffer(const char *name, signal_buffer *b, int comma) {
    print_hex_field(name, signal_buffer_data(b), signal_buffer_len(b), comma);
}

int main(void) {
    int result;
    signal_context_create(&global_context, 0);
    setup_test_crypto_provider(global_context);

    /* Bob's store (generates Bob's identity + registration id). */
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    uint32_t bob_reg_id = 0;
    signal_protocol_identity_get_local_registration_id(bob_store, &bob_reg_id);

    ratchet_identity_key_pair *bob_identity = 0;
    signal_protocol_identity_get_key_pair(bob_store, &bob_identity);

    ec_key_pair *bob_pre_key_pair = 0;
    curve_generate_key_pair(global_context, &bob_pre_key_pair);
    ec_key_pair *bob_signed_pre_key_pair = 0;
    curve_generate_key_pair(global_context, &bob_signed_pre_key_pair);

    /* omemo:2 signed pre-key signature is over the raw 32-byte Montgomery form. */
    signal_buffer *spk_omemo_serialized = 0;
    ec_public_key_serialize_omemo(&spk_omemo_serialized,
            ec_key_pair_get_public(bob_signed_pre_key_pair));
    signal_buffer *spk_signature_omemo = 0;
    curve_calculate_signature(global_context, &spk_signature_omemo,
            ratchet_identity_key_pair_get_private(bob_identity),
            signal_buffer_data(spk_omemo_serialized), signal_buffer_len(spk_omemo_serialized));

    const uint32_t pre_key_id = 31337;
    const uint32_t signed_pre_key_id = 22;

    session_pre_key_bundle *bob_bundle = 0;
    result = session_pre_key_bundle_create(&bob_bundle,
            bob_reg_id, bob_address.device_id,
            pre_key_id, ec_key_pair_get_public(bob_pre_key_pair),
            signed_pre_key_id, ec_key_pair_get_public(bob_signed_pre_key_pair),
            signal_buffer_data(spk_signature_omemo), signal_buffer_len(spk_signature_omemo),
            ratchet_identity_key_pair_get_public(bob_identity));
    if (result < 0) { fprintf(stderr, "bundle create failed: %d\n", result); return 1; }

    /* Alice establishes a session (omemo:2 = version 4) and encrypts. */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    session_builder *alice_builder = 0;
    session_builder_create(&alice_builder, alice_store, &bob_address, global_context);
    session_builder_set_version(alice_builder, 4);
    result = session_builder_process_pre_key_bundle(alice_builder, bob_bundle);
    if (result < 0) { fprintf(stderr, "process bundle failed: %d\n", result); return 1; }

    session_cipher *alice_cipher = 0;
    session_cipher_create(&alice_cipher, alice_store, &bob_address, global_context);
    session_cipher_set_version(alice_cipher, 4);

    const char *pt1 = "omemo:2 interop vector message one";
    const char *pt2 = "omemo:2 interop vector message two";
    ciphertext_message *m1 = 0, *m2 = 0;
    result = session_cipher_encrypt(alice_cipher, (const uint8_t *)pt1, strlen(pt1), &m1);
    if (result < 0) { fprintf(stderr, "encrypt 1 failed: %d\n", result); return 1; }
    result = session_cipher_encrypt(alice_cipher, (const uint8_t *)pt2, strlen(pt2), &m2);
    if (result < 0) { fprintf(stderr, "encrypt 2 failed: %d\n", result); return 1; }

    signal_buffer *id_priv = 0, *id_pub = 0, *spk_priv = 0, *spk_pub = 0, *pk_priv = 0, *pk_pub = 0;
    ec_private_key_serialize(&id_priv, ratchet_identity_key_pair_get_private(bob_identity));
    ec_public_key_serialize(&id_pub, ratchet_identity_key_pair_get_public(bob_identity));
    ec_private_key_serialize(&spk_priv, ec_key_pair_get_private(bob_signed_pre_key_pair));
    ec_public_key_serialize(&spk_pub, ec_key_pair_get_public(bob_signed_pre_key_pair));
    ec_private_key_serialize(&pk_priv, ec_key_pair_get_private(bob_pre_key_pair));
    ec_public_key_serialize(&pk_pub, ec_key_pair_get_public(bob_pre_key_pair));

    printf("{\n");
    printf("  \"description\": \"libomemo-c omemo:2 Alice->Bob, decrypted by libomemo.js Bob\",\n");
    printf("  \"bobRegistrationId\": %u,\n", bob_reg_id);
    printf("  \"signedPreKeyId\": %u,\n", signed_pre_key_id);
    printf("  \"preKeyId\": %u,\n", pre_key_id);
    /* Bob's identity key in the 32-byte Ed25519 form omemo:2 publishes, and the
       signed-pre-key signature over the raw 32-byte Montgomery form. These let
       the JS test verify a libomemo-c-produced bundle signature end to end. */
    ProtobufCBinaryData id_pub_ed = { 0, 0 };
    ec_public_key_serialize_protobuf_ed(&id_pub_ed,
            ratchet_identity_key_pair_get_public(bob_identity));

    dump_buffer("bobIdentityPriv", id_priv, 1);
    dump_buffer("bobIdentityPub", id_pub, 1);
    print_hex_field("bobIdentityPubEd", id_pub_ed.data, id_pub_ed.len, 1);
    dump_buffer("bobSignedPreKeyPriv", spk_priv, 1);
    dump_buffer("bobSignedPreKeyPub", spk_pub, 1);
    dump_buffer("bobSignedPreKeySignature", spk_signature_omemo, 1);
    dump_buffer("bobPreKeyPriv", pk_priv, 1);
    dump_buffer("bobPreKeyPub", pk_pub, 1);
    print_hex_field("plaintext1", (const uint8_t *)pt1, strlen(pt1), 1);
    dump_buffer("ciphertext1", ciphertext_message_get_serialized(m1), 1);
    print_hex_field("plaintext2", (const uint8_t *)pt2, strlen(pt2), 1);
    dump_buffer("ciphertext2", ciphertext_message_get_serialized(m2), 0);
    printf("}\n");

    return 0;
}

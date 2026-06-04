/*
 * One-time, sender-direction interop confirmation for OMEMO 2 (urn:xmpp:omemo:2).
 *
 * This is the reverse of gen-omemo2-vector.c: here libomemo-c plays the *receiver*
 * (Bob) and decrypts a key-exchange message that libomemo.js (Alice) produced. It
 * proves that what libomemo.js *emits* is accepted by the reference implementation
 * Dino uses — the one thing the in-repo test suite cannot check, since there both
 * sides are libomemo.js.
 *
 * Input is tools/omemo2-sender-vector.txt, written by the gated capture test
 * (test/omemo2-sender-capture.test.ts). It contains Bob's committed key material
 * plus libomemo.js's ciphertext and the expected plaintext. This program loads
 * Bob, decrypts the ciphertext, and checks the plaintext — exit 0 on success.
 *
 * Build (against a libomemo-c checkout built with cmake; see README.md):
 *   LC=~/src/libomemo-c
 *   gcc -O2 -w -I/tmp/stubinc -I"$LC/src" -I"$LC/tests" tools/dec-omemo2-vector.c \
 *       "$LC/tests/test_common.c" "$LC/tests/test_common_openssl.c" \
 *       "$LC/build/src/libomemo-c.a" -lcrypto -lprotobuf-c -o /tmp/dec-omemo2-vector
 *   /tmp/dec-omemo2-vector tools/omemo2-sender-vector.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/signal_protocol.h"
#include "session_cipher.h"
#include "session_builder.h"
#include "session_pre_key.h"
#include "curve.h"
#include "ratchet.h"
#include "protocol.h"
#include "test_common.h"

static signal_context *global_context;
static signal_protocol_address alice_address = { "alice@example.org", 17, 1 };

void debug_log(int level, const char *message, size_t len, void *user_data) {
    fprintf(stderr, "[libomemo-c] %.*s\n", (int)len, message);
}

/* ---- tiny "name hexvalue" file parser ------------------------------------ */

#define MAX_FIELDS 32
static char field_names[MAX_FIELDS][64];
static char field_values[MAX_FIELDS][1024];
static int field_count;

static const char *field(const char *name) {
    for (int i = 0; i < field_count; i++)
        if (strcmp(field_names[i], name) == 0) return field_values[i];
    fprintf(stderr, "missing field: %s\n", name);
    exit(1);
}

static uint8_t *hex2bin(const char *hex, size_t *out_len) {
    size_t len = strlen(hex) / 2;
    uint8_t *buf = malloc(len);
    for (size_t i = 0; i < len; i++) sscanf(hex + 2 * i, "%2hhx", &buf[i]);
    *out_len = len;
    return buf;
}

/* ---- a fixed-key identity store, so Bob uses the committed vector keys ---- */

typedef struct { signal_buffer *pub; signal_buffer *priv; uint32_t reg_id; } fixed_id_data;

static int fixed_get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data) {
    fixed_id_data *d = user_data;
    *public_data = signal_buffer_copy(d->pub);
    *private_data = signal_buffer_copy(d->priv);
    return 0;
}
static int fixed_get_local_registration_id(void *user_data, uint32_t *registration_id) {
    *registration_id = ((fixed_id_data *)user_data)->reg_id;
    return 0;
}
static int fixed_save_identity(const signal_protocol_address *a, uint8_t *k, size_t kl, void *u) { return 0; }
static int fixed_is_trusted_identity(const signal_protocol_address *a, uint8_t *k, size_t kl, void *u) { return 1; }

static ec_key_pair *load_key_pair(const char *pub_field, const char *priv_field) {
    size_t pub_len, priv_len;
    uint8_t *pub_b = hex2bin(field(pub_field), &pub_len);
    uint8_t *priv_b = hex2bin(field(priv_field), &priv_len);
    ec_public_key *pub = 0;
    ec_private_key *priv = 0;
    if (curve_decode_point(&pub, pub_b, pub_len, global_context) < 0) { fprintf(stderr, "decode pub %s\n", pub_field); exit(1); }
    if (curve_decode_private_point(&priv, priv_b, priv_len, global_context) < 0) { fprintf(stderr, "decode priv %s\n", priv_field); exit(1); }
    ec_key_pair *pair = 0;
    ec_key_pair_create(&pair, pub, priv);
    free(pub_b); free(priv_b);
    return pair;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "tools/omemo2-sender-vector.txt";
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    char line[2048];
    while (fgets(line, sizeof(line), f) && field_count < MAX_FIELDS) {
        char name[64], value[1024];
        if (sscanf(line, "%63s %1023s", name, value) == 2) {
            strcpy(field_names[field_count], name);
            strcpy(field_values[field_count], value);
            field_count++;
        }
    }
    fclose(f);

    signal_context_create(&global_context, 0);
    setup_test_crypto_provider(global_context);
    extern void debug_log(int, const char *, size_t, void *);
    signal_context_set_log_function(global_context, debug_log);

    /* Bob's store, with the random identity replaced by the committed one. */
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    size_t id_pub_len, id_priv_len;
    uint8_t *id_pub_b = hex2bin(field("bobIdentityPub"), &id_pub_len);
    uint8_t *id_priv_b = hex2bin(field("bobIdentityPriv"), &id_priv_len);
    fixed_id_data id_data;
    id_data.pub = signal_buffer_create(id_pub_b, id_pub_len);
    id_data.priv = signal_buffer_create(id_priv_b, id_priv_len);
    id_data.reg_id = (uint32_t)strtoul(field("bobRegistrationId"), 0, 10);

    signal_protocol_identity_key_store id_store = {
        .get_identity_key_pair = fixed_get_identity_key_pair,
        .get_local_registration_id = fixed_get_local_registration_id,
        .save_identity = fixed_save_identity,
        .is_trusted_identity = fixed_is_trusted_identity,
        .destroy_func = 0,
        .user_data = &id_data,
    };
    signal_protocol_store_context_set_identity_key_store(bob_store, &id_store);

    /* Store Bob's pre key and signed pre key under the ids Alice referenced. */
    uint32_t pre_key_id = (uint32_t)strtoul(field("preKeyId"), 0, 10);
    uint32_t signed_pre_key_id = (uint32_t)strtoul(field("signedPreKeyId"), 0, 10);

    ec_key_pair *pre_key_pair = load_key_pair("bobPreKeyPub", "bobPreKeyPriv");
    session_pre_key *pre_key_record = 0;
    session_pre_key_create(&pre_key_record, pre_key_id, pre_key_pair);
    signal_protocol_pre_key_store_key(bob_store, pre_key_record);

    ec_key_pair *signed_pre_key_pair = load_key_pair("bobSignedPreKeyPub", "bobSignedPreKeyPriv");
    /* Bob never verifies its own signed-pre-key signature when decrypting, so a
       placeholder signature is fine here. */
    uint8_t dummy_sig[64] = { 0 };
    session_signed_pre_key *signed_pre_key_record = 0;
    session_signed_pre_key_create(&signed_pre_key_record, signed_pre_key_id, time(0),
            signed_pre_key_pair, dummy_sig, sizeof(dummy_sig), dummy_sig, sizeof(dummy_sig));
    signal_protocol_signed_pre_key_store_key(bob_store, signed_pre_key_record);

    /* Decode libomemo.js's key-exchange message and decrypt it. */
    size_t ct_len, pt_len;
    uint8_t *ct = hex2bin(field("ciphertext"), &ct_len);
    uint8_t *expected_pt = hex2bin(field("plaintext"), &pt_len);

    pre_key_signal_message *incoming = 0;
    int result = pre_key_signal_message_deserialize_omemo(&incoming, ct, ct_len,
            id_data.reg_id, global_context);
    if (result < 0) { fprintf(stderr, "FAIL: deserialize_omemo: %d\n", result); return 1; }

    session_cipher *bob_cipher = 0;
    session_cipher_create(&bob_cipher, bob_store, &alice_address, global_context);
    session_cipher_set_version(bob_cipher, 4);

    signal_buffer *plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_cipher, incoming, 0, &plaintext);
    if (result < 0) { fprintf(stderr, "FAIL: decrypt: %d\n", result); return 1; }

    size_t got_len = signal_buffer_len(plaintext);
    if (got_len != pt_len || memcmp(signal_buffer_data(plaintext), expected_pt, pt_len) != 0) {
        fprintf(stderr, "FAIL: plaintext mismatch (got %zu bytes, expected %zu)\n", got_len, pt_len);
        return 1;
    }

    printf("OK: libomemo-c decrypted libomemo.js's omemo:2 message (%zu bytes): \"%.*s\"\n",
           got_len, (int)got_len, signal_buffer_data(plaintext));
    return 0;
}

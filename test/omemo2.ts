import { assert } from "chai";
import {
    SessionBuilder,
    SessionCipher,
    OMEMOAddress,
    KeyHelper,
    util,
    internalCrypto,
} from "../src/index";
import { SessionRecord } from "../src/session/record";
import { generateIdentity, assertEqualArrayBuffers, hexToArrayBuffer } from "./utils";
import { LIBOMEMO_C_VECTOR, libomemoCBobBundle } from "./omemo2-vector";
import InMemoryStore from "../src/session/store";
import type { OMEMOStore, PreKeyBundle } from "../src/session/types";
import type { OMEMOVersion } from "../src/session/protocol-profile";

/**
 * Build a PreKey bundle for the given version. For omemo:2 the identity key is
 * published in its Ed25519 form (as a real consumer would do).
 */
async function makeBundle(
    store: OMEMOStore,
    version: OMEMOVersion,
    preKeyId: number,
    spkId: number
): Promise<PreKeyBundle> {
    const identity = (await store.getIdentityKeyPair())!;
    const registrationId = (await store.getLocalRegistrationId())!;
    const [preKey, signedPreKey] = await Promise.all([
        KeyHelper.generatePreKey(preKeyId),
        KeyHelper.generateSignedPreKey(identity, spkId, version),
    ]);
    await store.storePreKey(preKeyId, preKey.keyPair);
    await store.storeSignedPreKey(spkId, signedPreKey.keyPair);

    const identityKey =
        version === "urn:xmpp:omemo:2"
            ? await internalCrypto.curvePubKeyToEd25519PubKey(identity.pubKey)
            : identity.pubKey;

    return {
        identityKey,
        registrationId,
        preKey: { keyId: preKeyId, publicKey: preKey.keyPair.pubKey },
        signedPreKey: {
            keyId: spkId,
            publicKey: signedPreKey.keyPair.pubKey,
            signature: signedPreKey.signature,
        },
    };
}

describe("OMEMO end-to-end (both versions)", function () {
    for (const version of ["eu.siacs.conversations.axolotl", "urn:xmpp:omemo:2"] as const) {
        describe(version, function () {
            const ALICE = new OMEMOAddress("alice@example.org", 1);
            const BOB = new OMEMOAddress("bob@example.org", 1);
            let aliceStore: InMemoryStore;
            let bobStore: InMemoryStore;
            let aliceCipher: SessionCipher;
            let bobCipher: SessionCipher;

            before(async function () {
                aliceStore = new InMemoryStore();
                bobStore = new InMemoryStore();
                await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)]);
                const bundle = await makeBundle(bobStore, version, 1337, 1);
                const builder = new SessionBuilder(aliceStore, BOB, version);
                await builder.processPreKey(bundle);
                aliceCipher = new SessionCipher(aliceStore, BOB, version);
                bobCipher = new SessionCipher(bobStore, ALICE, version);
            });

            it("stores the protocol version on the session", function () {
                const record = SessionRecord.deserialize(aliceStore.loadSession(BOB.toString())!);
                assert.strictEqual(record.getOpenSession()!.protocolVersion, version);
            });

            it("stores the Curve identity form internally and keys trust on the wire form", async function () {
                const record = SessionRecord.deserialize(aliceStore.loadSession(BOB.toString())!);
                const indexInfo = record.getOpenSession()!.indexInfo;

                // remoteIdentityKey is always the internal 33-byte 0x05-Curve form.
                assert.strictEqual(indexInfo.remoteIdentityKey.byteLength, 33);
                assert.strictEqual(new Uint8Array(indexInfo.remoteIdentityKey)[0], 5);

                const bobIdentity = (await bobStore.getIdentityKeyPair())!;
                const savedTrustKey = aliceStore.loadIdentityKey(BOB.toString())!;

                if (version === "urn:xmpp:omemo:2") {
                    // Trust is keyed on the published 32-byte Ed25519 form...
                    const bobEd = await internalCrypto.curvePubKeyToEd25519PubKey(
                        bobIdentity.pubKey
                    );
                    assert.strictEqual(indexInfo.remoteIdentityKeyEd!.byteLength, 32);
                    assertEqualArrayBuffers(indexInfo.remoteIdentityKeyEd!, bobEd);
                    assertEqualArrayBuffers(savedTrustKey, bobEd);
                } else {
                    // 0.3.0 has no Ed form; trust falls back to the Curve form.
                    assert.isUndefined(indexInfo.remoteIdentityKeyEd);
                    assertEqualArrayBuffers(savedTrustKey, bobIdentity.pubKey);
                }
            });

            it("Alice -> Bob via a key-exchange message", async function () {
                const msg = util.toArrayBuffer("key+HMAC tuple #1") as ArrayBuffer;
                const ct = await aliceCipher.encrypt(msg);
                assert.strictEqual(ct.type, 3);
                if (version === "urn:xmpp:omemo:2") {
                    assert.isTrue(ct.kex);
                }
                const pt = await bobCipher.decryptPreKeyWhisperMessage(ct.body, "binary");
                assertEqualArrayBuffers(pt, msg);
            });

            it("Bob -> Alice (ratchet step) then Alice -> Bob on an established session", async function () {
                const reply = util.toArrayBuffer("reply tuple") as ArrayBuffer;
                const ct2 = await bobCipher.encrypt(reply);
                assert.strictEqual(ct2.type, 1);
                const pt2 = await aliceCipher.decryptWhisperMessage(ct2.body, "binary");
                assertEqualArrayBuffers(pt2, reply);

                const third = util.toArrayBuffer("third tuple") as ArrayBuffer;
                const ct3 = await aliceCipher.encrypt(third);
                assert.strictEqual(ct3.type, 1);
                const pt3 = await bobCipher.decryptWhisperMessage(ct3.body, "binary");
                assertEqualArrayBuffers(pt3, third);
            });

            it("handles out-of-order delivery", async function () {
                const m1 = util.toArrayBuffer("ooo-1") as ArrayBuffer;
                const m2 = util.toArrayBuffer("ooo-2") as ArrayBuffer;
                const c1 = await aliceCipher.encrypt(m1);
                const c2 = await aliceCipher.encrypt(m2);
                // Deliver the second message first.
                const p2 = await bobCipher.decryptWhisperMessage(c2.body, "binary");
                const p1 = await bobCipher.decryptWhisperMessage(c1.body, "binary");
                assertEqualArrayBuffers(p2, m2);
                assertEqualArrayBuffers(p1, m1);
            });
        });
    }
});

describe("OMEMO 2 trust-key enforcement", function () {
    it("refuses to operate on an omemo:2 session missing the Ed25519 identity key", async function () {
        const BOB = new OMEMOAddress("bob@example.org", 1);
        const aliceStore = new InMemoryStore();
        const bobStore = new InMemoryStore();
        await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)]);
        const bundle = await makeBundle(bobStore, "urn:xmpp:omemo:2", 1337, 1);
        await new SessionBuilder(aliceStore, BOB, "urn:xmpp:omemo:2").processPreKey(bundle);

        // Tamper with the stored session: drop the Ed form so the trust lookup
        // would otherwise silently fall back to the Curve form.
        const record = SessionRecord.deserialize(aliceStore.loadSession(BOB.toString())!);
        delete record.getOpenSession()!.indexInfo.remoteIdentityKeyEd;
        aliceStore.storeSession(BOB.toString(), record.serialize());

        const cipher = new SessionCipher(aliceStore, BOB, "urn:xmpp:omemo:2");
        let err: Error | undefined;
        try {
            await cipher.encrypt(util.toArrayBuffer("nope") as ArrayBuffer);
        } catch (e) {
            err = e as Error;
        }
        assert.instanceOf(err, Error);
        assert.match(err.message, /missing the Ed25519 identity key/);
    });
});

describe("0.3.0 registrationId enforcement", function () {
    it("refuses to send a key-exchange message without a local registrationId", async function () {
        const BOB = new OMEMOAddress("bob@example.org", 1);
        const aliceStore = new InMemoryStore();
        const bobStore = new InMemoryStore();
        await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)]);
        const bundle = await makeBundle(bobStore, "eu.siacs.conversations.axolotl", 1337, 1);
        await new SessionBuilder(
            aliceStore,
            BOB,
            "eu.siacs.conversations.axolotl"
        ).processPreKey(bundle);

        // Drop Alice's local registrationId; the pending key-exchange needs it for 0.3.0.
        aliceStore.remove("registrationId");

        const cipher = new SessionCipher(aliceStore, BOB, "eu.siacs.conversations.axolotl");
        let err: Error | undefined;
        try {
            await cipher.encrypt(util.toArrayBuffer("hi") as ArrayBuffer);
        } catch (e) {
            err = e as Error;
        }
        assert.instanceOf(err, Error);
        assert.match(err.message, /no local registrationId/);
    });
});

describe("OMEMO 2 cross-implementation vector (libomemo-c)", function () {
    const ALICE = new OMEMOAddress("alice@example.org", 1);
    let bobCipher: SessionCipher;

    before(function () {
        const v = LIBOMEMO_C_VECTOR;
        const store = new InMemoryStore();
        store.put("identityKey", {
            pubKey: hexToArrayBuffer(v.bobIdentityPub),
            privKey: hexToArrayBuffer(v.bobIdentityPriv),
        });
        store.put("registrationId", v.bobRegistrationId);
        store.storeSignedPreKey(v.signedPreKeyId, {
            pubKey: hexToArrayBuffer(v.bobSignedPreKeyPub),
            privKey: hexToArrayBuffer(v.bobSignedPreKeyPriv),
        });
        store.storePreKey(v.preKeyId, {
            pubKey: hexToArrayBuffer(v.bobPreKeyPub),
            privKey: hexToArrayBuffer(v.bobPreKeyPriv),
        });
        bobCipher = new SessionCipher(store, ALICE, "urn:xmpp:omemo:2");
    });

    it("decrypts libomemo-c's key-exchange message", async function () {
        const pt = await bobCipher.decryptPreKeyWhisperMessage(
            hexToArrayBuffer(LIBOMEMO_C_VECTOR.ciphertext1),
            "binary"
        );
        assertEqualArrayBuffers(pt, hexToArrayBuffer(LIBOMEMO_C_VECTOR.plaintext1));
    });

    it("decrypts a second message on the same chain (counter advances)", async function () {
        const pt = await bobCipher.decryptPreKeyWhisperMessage(
            hexToArrayBuffer(LIBOMEMO_C_VECTOR.ciphertext2),
            "binary"
        );
        assertEqualArrayBuffers(pt, hexToArrayBuffer(LIBOMEMO_C_VECTOR.plaintext2));
    });
});

/**
 * The other interop direction: libomemo.js plays Alice and processes a PreKey
 * bundle published by libomemo-c (Bob). This is the only test that exercises
 * omemo:2 signed-pre-key signature *verification* against a real external
 * signature — the security-critical decision that omemo:2 signs the SPK over the
 * raw 32-byte Montgomery form, which the receiver-side decrypt vectors never reach.
 */
describe("OMEMO 2 cross-implementation bundle verification (libomemo-c)", function () {
    const BOB = new OMEMOAddress("bob@example.org", 1);
    const v = LIBOMEMO_C_VECTOR;

    it("derives the same Ed25519 identity key libomemo-c published", async function () {
        const derivedEd = await internalCrypto.curvePubKeyToEd25519PubKey(
            hexToArrayBuffer(v.bobIdentityPub)
        );
        assertEqualArrayBuffers(derivedEd, hexToArrayBuffer(v.bobIdentityPubEd));
    });

    it("accepts libomemo-c's signed-pre-key signature", async function () {
        const aliceStore = new InMemoryStore();
        await generateIdentity(aliceStore);
        const builder = new SessionBuilder(aliceStore, BOB, "urn:xmpp:omemo:2");
        // Resolves only if the signature over the raw 32-byte Montgomery SPK verifies.
        await builder.processPreKey(libomemoCBobBundle());
        const record = SessionRecord.deserialize(aliceStore.loadSession(BOB.toString())!);
        assert.strictEqual(record.getOpenSession()!.protocolVersion, "urn:xmpp:omemo:2");
    });

    it("rejects a tampered signed-pre-key signature", async function () {
        const tampered = hexToArrayBuffer(v.bobSignedPreKeySignature);
        new Uint8Array(tampered)[0] ^= 0xff;

        const aliceStore = new InMemoryStore();
        await generateIdentity(aliceStore);
        const builder = new SessionBuilder(aliceStore, BOB, "urn:xmpp:omemo:2");
        let err: Error | undefined;
        try {
            await builder.processPreKey(libomemoCBobBundle(tampered));
        } catch (e) {
            err = e as Error;
        }
        assert.instanceOf(err, Error);
    });
});

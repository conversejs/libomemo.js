import { assert } from "chai";
import { getRandomBytes, internalCrypto } from "../src/crypto";
import { Curve25519 } from "../src/curve";
import { getProtocolProfile } from "../src/session/protocol-profile";
import { assertEqualArrayBuffers, hexToArrayBuffer, hexToUint8Array } from "./utils";

const curve = new Curve25519();

describe("Curve25519 <-> Ed25519 conversion", function () {
    it("curve->ed->curve round-trips, with a forced-zero Ed25519 sign bit", async function () {
        for (let i = 0; i < 20; i++) {
            const kp = await curve.generateKeyPair();
            const rawCurvePub = kp.pubKey.slice(1); // drop the 0x05 type prefix

            const edPub = await curve.curvePubKeyToEd25519PubKey(kp.pubKey);
            assert.strictEqual(edPub.byteLength, 32);
            // libomemo-c derives the published IdentityKey with sign bit 0.
            assert.strictEqual(new Uint8Array(edPub)[31] & 0x80, 0);

            const curveBack = await curve.ed25519PubKeyToCurvePubKey(edPub);
            assert.strictEqual(curveBack.byteLength, 32);

            // montx_to_edy then edy_to_montx returns the original u-coordinate.
            assertEqualArrayBuffers(curveBack, rawCurvePub);
        }
    });

    it("matches libomemo-c for a known Curve25519->Ed25519 identity-key vector", async function () {
        // Verified byte-for-byte against libomemo-c's own field code
        // (fe_montx_to_edy / fe_edy_to_montx — the implementation Dino uses).
        // Pins the sign-bit-0 Ed25519 identity-key encoding used in the omemo:2
        // `ik` field and the authentication associated data.
        const curveU = "d0b316a43592ebd178b7043f2da97ffd4a46ad738678060189d926977d780e7a";
        const expectedEd = "c097c5a9735ab32d856058c3a7fc81760490ba1eae83df2ccd0f9373e7fdbe74";

        const curvePub33 = new Uint8Array(33);
        curvePub33[0] = 5;
        curvePub33.set(hexToUint8Array(curveU), 1);

        const ed = await curve.curvePubKeyToEd25519PubKey(curvePub33.buffer);
        assertEqualArrayBuffers(ed, hexToArrayBuffer(expectedEd));

        // ...and the reverse recovers the original Curve25519 u-coordinate.
        const back = await curve.ed25519PubKeyToCurvePubKey(ed);
        assertEqualArrayBuffers(back, hexToArrayBuffer(curveU));
    });

    it("rejects a non-32-byte Ed25519 key", async function () {
        let err;
        try {
            await curve.ed25519PubKeyToCurvePubKey(new ArrayBuffer(31));
        } catch (e) {
            err = e;
        }
        assert.instanceOf(err, Error);
    });
});

describe("ProtocolProfile", function () {
    it("exposes the expected per-version constants", function () {
        const v3 = getProtocolProfile("eu.siacs.conversations.axolotl");
        assert.strictEqual(v3.messageKeyInfo, "WhisperMessageKeys");
        assert.strictEqual(v3.x3dhInfo, "WhisperText");
        assert.strictEqual(v3.rootChainInfo, "WhisperRatchet");
        assert.strictEqual(v3.requiresRegistrationId, true);
        assert.strictEqual(v3.usesEdIdentityKey, false);

        const v2 = getProtocolProfile("urn:xmpp:omemo:2");
        assert.strictEqual(v2.messageKeyInfo, "OMEMO Message Key Material");
        assert.strictEqual(v2.x3dhInfo, "OMEMO X3DH");
        assert.strictEqual(v2.rootChainInfo, "OMEMO Root Chain");
        assert.strictEqual(v2.requiresRegistrationId, false);
        assert.strictEqual(v2.usesEdIdentityKey, true);
    });

    it("throws for an unknown version", function () {
        assert.throws(() => getProtocolProfile("nope" as never), /Unsupported OMEMO version/);
    });

    for (const version of ["eu.siacs.conversations.axolotl", "urn:xmpp:omemo:2"] as const) {
        describe(version, function () {
            const profile = getProtocolProfile(version);

            it("round-trips a ratchet message and verifies its MAC", async function () {
                const ourKp = await internalCrypto.createKeyPair();
                const remoteKp = await internalCrypto.createKeyPair();
                const ephemeralKp = await internalCrypto.createKeyPair();
                const authKey = getRandomBytes(32);
                const ad = getRandomBytes(64);

                const parts = {
                    ephemeralKey: ephemeralKp.pubKey,
                    counter: 4,
                    previousCounter: 1,
                    ciphertext: getRandomBytes(48),
                };

                const encodedInner = await profile.encodeInner(parts);
                const mac = await profile.computeMac(authKey, encodedInner, {
                    ourIdentityKey: ourKp.pubKey,
                    remoteIdentityKey: remoteKp.pubKey,
                    direction: "sending",
                    ad,
                });
                assert.strictEqual(mac.byteLength, version === "eu.siacs.conversations.axolotl" ? 8 : 16);

                const body = await profile.frameMessage(encodedInner, mac);
                const exact = body.buffer.slice(
                    body.byteOffset,
                    body.byteOffset + body.byteLength
                ) as ArrayBuffer;
                const parsed = await profile.parseMessage(exact);

                assert.strictEqual(parsed.counter, 4);
                assert.strictEqual(parsed.previousCounter, 1);
                assertEqualArrayBuffers(parsed.ciphertext, parts.ciphertext);
                assertEqualArrayBuffers(parsed.ephemeralKey, ephemeralKp.pubKey);

                // Receiver verifies with the swapped direction (0.3.0); ad is symmetric.
                await profile.verifyMac(
                    authKey,
                    parsed.encodedInner,
                    {
                        ourIdentityKey: remoteKp.pubKey,
                        remoteIdentityKey: ourKp.pubKey,
                        direction: "receiving",
                        ad,
                    },
                    parsed.mac
                );
            });

            it("round-trips a key-exchange message", async function () {
                const ourKp = await internalCrypto.createKeyPair();
                const baseKp = await internalCrypto.createKeyPair();
                const authKey = getRandomBytes(32);
                const ad = getRandomBytes(64);

                const inner = await profile.encodeInner({
                    ephemeralKey: baseKp.pubKey,
                    counter: 0,
                    previousCounter: 0,
                    ciphertext: getRandomBytes(48),
                });
                const mac = await profile.computeMac(authKey, inner, {
                    ourIdentityKey: ourKp.pubKey,
                    remoteIdentityKey: ourKp.pubKey,
                    direction: "sending",
                    ad,
                });
                const framed = await profile.frameMessage(inner, mac);

                const kexBody = await profile.encodeKeyExchange(
                    {
                        registrationId: 1234,
                        preKeyId: 77,
                        signedPreKeyId: 88,
                        baseKey: baseKp.pubKey,
                        ourIdentityKey: ourKp,
                    },
                    framed
                );
                const exact = kexBody.buffer.slice(
                    kexBody.byteOffset,
                    kexBody.byteOffset + kexBody.byteLength
                ) as ArrayBuffer;
                const parsed = await profile.parseKeyExchange(exact);

                assert.strictEqual(parsed.preKeyId, 77);
                assert.strictEqual(parsed.signedPreKeyId, 88);
                assertEqualArrayBuffers(parsed.baseKey, baseKp.pubKey);
                // Both versions recover the Curve25519 identity key.
                assertEqualArrayBuffers(parsed.identityKey, ourKp.pubKey);

                if (version === "eu.siacs.conversations.axolotl") {
                    assert.strictEqual(parsed.registrationId, 1234);
                    assert.isUndefined(parsed.identityKeyEd);
                } else {
                    assert.isDefined(parsed.identityKeyEd);
                    assert.strictEqual(parsed.identityKeyEd?.byteLength, 32);
                }

                const reparsed = await profile.parseMessage(parsed.message);
                assert.strictEqual(reparsed.counter, 0);
            });
        });
    }
});

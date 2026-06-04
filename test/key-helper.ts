import { assert, expect } from "chai";
import { KeyHelper } from "../src/index.js";
import { internalCrypto } from "../src/crypto.js";

describe("KeyHelper", function () {
    function validateKeyPair(keyPair: { pubKey: ArrayBuffer; privKey: ArrayBuffer }): void {
        assert.isDefined(keyPair.pubKey);
        assert.isDefined(keyPair.privKey);
        assert.strictEqual(keyPair.privKey.byteLength, 32);
        assert.strictEqual(keyPair.pubKey.byteLength, 33);
        assert.strictEqual(new Uint8Array(keyPair.pubKey)[0], 5);
    }

    describe("generateIdentityKeyPair", function () {
        it("works", async function () {
            const keyPair = await KeyHelper.generateIdentityKeyPair();
            validateKeyPair(keyPair);
        });
    });

    describe("generateRegistrationId", function () {
        it("generates a 14-bit integer", function () {
            const registrationId = KeyHelper.generateRegistrationId();
            assert.isNumber(registrationId);
            assert(registrationId >= 0);
            assert(registrationId < 16384);
            assert.strictEqual(registrationId, Math.round(registrationId)); // integer
        });
    });

    describe("generatePreKey", function () {
        it("generates a preKey", async function () {
            const result = await KeyHelper.generatePreKey(1337);
            validateKeyPair(result.keyPair);
            assert.strictEqual(result.keyId, 1337);
        });

        it("throws on bad keyId", async function () {
            let error;
            try {
                await KeyHelper.generatePreKey("bad");
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(TypeError);
        });
    });

    describe("generateSignedPreKey", function () {
        it("generates a preKey (0.3.0: signature over the 33-byte form)", async function () {
            const identityKey = await KeyHelper.generateIdentityKeyPair();
            const result = await KeyHelper.generateSignedPreKey(identityKey, 1337, "eu.siacs.conversations.axolotl");
            validateKeyPair(result.keyPair);
            assert.strictEqual(result.keyId, 1337);
            await internalCrypto.Ed25519Verify(
                identityKey.pubKey,
                result.keyPair.pubKey,
                result.signature
            );
        });

        it("generates a preKey (omemo:2: signature over the raw 32-byte form)", async function () {
            const identityKey = await KeyHelper.generateIdentityKeyPair();
            const result = await KeyHelper.generateSignedPreKey(identityKey, 1337, "urn:xmpp:omemo:2");
            validateKeyPair(result.keyPair);
            // omemo:2 signs the 32-byte Curve25519 form (no 0x05 prefix).
            await internalCrypto.Ed25519Verify(
                identityKey.pubKey,
                result.keyPair.pubKey.slice(1),
                result.signature
            );
        });

        it("throws on bad keyId", async function () {
            let error;
            try {
                await KeyHelper.generatePreKey("bad");
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(TypeError);
        });
    });
});

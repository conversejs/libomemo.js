import { assert, expect } from "chai";
import { KeyHelper } from "../src/index.js";

describe("KeyHelper", function () {
    function validateKeyPair(keyPair) {
        assert.isDefined(keyPair.pubKey);
        assert.isDefined(keyPair.privKey);
        assert.strictEqual(keyPair.privKey.byteLength, 32);
        assert.strictEqual(keyPair.pubKey.byteLength, 33);
        assert.strictEqual(new Uint8Array(keyPair.pubKey)[0], 5);
    }

    describe("generateIdentityKeyPair", function () {
        it("works", function () {
            KeyHelper.generateIdentityKeyPair().then(function (keyPair) {
                validateKeyPair(keyPair);
            });
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
        it("generates a preKey", function (done) {
            KeyHelper.generatePreKey(1337)
                .then(function (result) {
                    validateKeyPair(result.keyPair);
                    assert.strictEqual(result.keyId, 1337);
                })
                .then(done, done);
        });

        it("throws on bad keyId", async function () {
            const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
            let error;
            try {
                await KeyHelper.generatePreKey(identityKeyPair, "bad");
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(TypeError);
        });
    });

    describe("generateSignedPreKey", function () {
        it("generates a preKey", function (done) {
            KeyHelper.generateIdentityKeyPair()
                .then((identityKey) => {
                    KeyHelper.generateSignedPreKey(identityKey, 1337).then((result) => {
                        validateKeyPair(result.keyPair);
                        assert.strictEqual(result.keyId, 1337);
                        //todo: validate result.signature
                    });
                })
                .then(done, done);
        });

        it("throws on bad keyId", async function () {
            const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
            let error;
            try {
                await KeyHelper.generateSignedPreKey(identityKeyPair, "bad");
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(TypeError);
        });
    });
});

import { assert, expect } from "chai";
import { Curve } from "../src/index.js";
import { assertEqualArrayBuffers } from "./utils.js";

describe("Curve", function () {
    describe("generateKeyPair", function () {
        it("returns a 32-byte private key and a 33-byte public key with 0x05 prefix", async function () {
            const keyPair = await Curve.async.generateKeyPair();
            assert.instanceOf(keyPair.privKey, ArrayBuffer);
            assert.instanceOf(keyPair.pubKey, ArrayBuffer);
            assert.strictEqual(keyPair.privKey.byteLength, 32);
            assert.strictEqual(keyPair.pubKey.byteLength, 33);
            assert.strictEqual(new Uint8Array(keyPair.pubKey)[0], 5);
        });

        it("generates different keys each time", async function () {
            const kp1 = await Curve.async.generateKeyPair();
            const kp2 = await Curve.async.generateKeyPair();
            assert.notStrictEqual(kp1.privKey, kp2.privKey);
            assert.notStrictEqual(kp1.pubKey, kp2.pubKey);
        });
    });

    describe("createKeyPair", function () {
        it("derives the public key from a given private key", async function () {
            const kp = await Curve.async.generateKeyPair();
            const kp2 = await Curve.async.createKeyPair(kp.privKey);
            assertEqualArrayBuffers(kp.pubKey, kp2.pubKey);
            assertEqualArrayBuffers(kp.privKey, kp2.privKey);
        });

        it("throws for invalid private key (not ArrayBuffer)", async function () {
            let error;
            try {
                await Curve.async.createKeyPair("notabuffer");
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid private key: expected ArrayBuffer");
        });

        it("throws for private key with wrong length", async function () {
            const shortKey = new ArrayBuffer(16);

            let error;
            try {
                await Curve.async.createKeyPair(shortKey);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid private key");
        });
    });

    describe("calculateAgreement", function () {
        it("produces identical shared secrets for both parties", async function () {
            const alice = await Curve.async.generateKeyPair();
            const bob = await Curve.async.generateKeyPair();

            const aliceShared = Curve.async.calculateAgreement(bob.pubKey, alice.privKey);
            const bobShared = Curve.async.calculateAgreement(alice.pubKey, bob.privKey);

            assertEqualArrayBuffers(aliceShared, bobShared);
        });

        it("produces a 32-byte shared secret", async function () {
            const alice = await Curve.async.generateKeyPair();
            const bob = await Curve.async.generateKeyPair();

            const shared = await Curve.async.calculateAgreement(bob.pubKey, alice.privKey);
            assert.instanceOf(shared, ArrayBuffer);
            assert.strictEqual(shared.byteLength, 32);
        });

        it("throws for invalid public key format (wrong length)", async function () {
            const kp = await Curve.async.generateKeyPair();
            const badPub = new ArrayBuffer(10);
            let error;
            try {
                await Curve.async.calculateAgreement(badPub, kp.privKey);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid public key");
        });
    });

    describe("calculateSignature", function () {
        it("produces a 64-byte signature", async function () {
            const kp = await Curve.async.generateKeyPair();

            const message = new Uint8Array([1, 2, 3, 4, 5]).buffer;
            const sig = await Curve.async.calculateSignature(kp.privKey, message);

            assert.instanceOf(sig, ArrayBuffer);
            assert.strictEqual(sig.byteLength, 64);
        });

        it("throws for undefined message", async function () {
            const kp = await Curve.async.generateKeyPair();
            let error;
            try {
                await Curve.async.calculateSignature(kp.privKey, undefined);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid message");
        });
    });

    describe("verifySignature", function () {
        it("verifies a valid signature (resolves with undefined)", async function () {
            const kp = await Curve.async.generateKeyPair();
            const message = new TextEncoder().encode("test message").buffer;

            const sig = await Curve.async.calculateSignature(kp.privKey, message);
            const result = await Curve.async.verifySignature(kp.pubKey, message, sig);

            assert.isUndefined(result);
        });

        it("rejects for a tampered message", async function () {
            const kp = await Curve.async.generateKeyPair();
            const message = new TextEncoder().encode("test message").buffer;
            const badMsg = new TextEncoder().encode("bad message").buffer;
            const sig = await Curve.async.calculateSignature(kp.privKey, message);

            let error;
            try {
                await Curve.async.verifySignature(kp.pubKey, badMsg, sig);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid signature");
        });

        it("rejects for a tampered signature", async function () {
            const kp = await Curve.async.generateKeyPair();
            const message = new TextEncoder().encode("test message").buffer;
            const sig = await Curve.async.calculateSignature(kp.privKey, message);
            const badSig = new Uint8Array(sig);
            badSig[0] = (badSig[0] + 1) & 0xff;

            let error;
            try {
                await Curve.async.verifySignature(kp.pubKey, message, badSig.buffer);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid signature");
        });

        it("throws for invalid public key format", async function () {
            const badPub = new ArrayBuffer(10);
            const msg = new ArrayBuffer(5);
            const sig = new ArrayBuffer(64);
            let error;
            try {
                await Curve.async.verifySignature(badPub, msg, sig);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid public key");
        });

        it("throws for invalid signature length", async function () {
            const kp = await Curve.async.generateKeyPair();
            const msg = new ArrayBuffer(5);
            const badSig = new ArrayBuffer(10);
            let error;
            try {
                await Curve.async.verifySignature(kp.pubKey, msg, badSig);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Invalid signature");
        });

        it("works correctly across many different key pairs", async function () {
            const NUM_PAIRS = 50;
            const message = new TextEncoder().encode("multi-key-pair test message").buffer;
            const keyPairs = [];

            for (let i = 0; i < NUM_PAIRS; i++) {
                keyPairs.push(await Curve.async.generateKeyPair());
            }

            for (let i = 0; i < NUM_PAIRS; i++) {
                const sig = await Curve.async.calculateSignature(keyPairs[i].privKey, message);
                assert.strictEqual(sig.byteLength, 64);

                await Curve.async.verifySignature(keyPairs[i].pubKey, message, sig);

                for (let j = 0; j < NUM_PAIRS; j++) {
                    if (j === i) continue;
                    try {
                        await Curve.async.verifySignature(keyPairs[j].pubKey, message, sig);
                        assert.fail(`Signature from key ${i} should not verify with key ${j}`);
                    } catch (err) {
                        if (err.message !== "Invalid signature") {
                            throw err;
                        }
                    }
                }
            }
        });
    });
});

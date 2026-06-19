import { assert, expect } from "chai";
import { Curve25519 } from "../src/curve.js";
import { assertEqualArrayBuffers } from "./utils.js";

const curve = new Curve25519();

describe("Curve25519", function () {
    describe("generateKeyPair", function () {
        it("returns a 32-byte private key and a 33-byte public key with 0x05 prefix", async function () {
            const keyPair = await curve.generateKeyPair();
            assert.instanceOf(keyPair.privKey, ArrayBuffer);
            assert.instanceOf(keyPair.pubKey, ArrayBuffer);
            assert.strictEqual(keyPair.privKey.byteLength, 32);
            assert.strictEqual(keyPair.pubKey.byteLength, 33);
            assert.strictEqual(new Uint8Array(keyPair.pubKey)[0], 5);
        });

        it("generates different keys each time", async function () {
            const kp1 = await curve.generateKeyPair();
            const kp2 = await curve.generateKeyPair();
            assert.notStrictEqual(kp1.privKey, kp2.privKey);
            assert.notStrictEqual(kp1.pubKey, kp2.pubKey);
        });
    });

    describe("createKeyPair", function () {
        it("derives the public key from a given private key", async function () {
            const kp = await curve.generateKeyPair();
            const kp2 = await curve.createKeyPair(kp.privKey);
            assertEqualArrayBuffers(kp.pubKey, kp2.pubKey);
            assertEqualArrayBuffers(kp.privKey, kp2.privKey);
        });

        // Clamping must not mutate or alias the caller's input buffer.
        it("does not mutate or alias the input private key", async function () {
            // All-0xFF is not clamped, so clamping is observable: byte 0 -> 0xF8,
            // byte 31 -> 0x7F.
            const input = new Uint8Array(32).fill(0xff).buffer;
            const keyPair = await curve.createKeyPair(input);

            // The caller's buffer is left exactly as supplied.
            assert.isTrue(new Uint8Array(input).every((b) => b === 0xff));
            // The returned key is an independent buffer, not the input.
            assert.notStrictEqual(keyPair.privKey, input);
            // ...and it carries the clamped scalar.
            const clamped = new Uint8Array(keyPair.privKey);
            assert.strictEqual(clamped[0], 0xf8);
            assert.strictEqual(clamped[31], 0x7f);
        });

        it("throws for invalid private key (not ArrayBuffer)", async function () {
            let error;
            try {
                await curve.createKeyPair("notabuffer" as unknown as ArrayBuffer);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(
                (error as Error).message,
                "Invalid private key: expected ArrayBuffer"
            );
        });

        it("throws for private key with wrong length", async function () {
            const shortKey = new ArrayBuffer(16);

            let error;
            try {
                await curve.createKeyPair(shortKey);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid private key");
        });
    });

    describe("calculateAgreement", function () {
        it("produces identical shared secrets for both parties", async function () {
            const alice = await curve.generateKeyPair();
            const bob = await curve.generateKeyPair();

            const aliceShared = await curve.calculateAgreement(bob.pubKey, alice.privKey);
            const bobShared = await curve.calculateAgreement(alice.pubKey, bob.privKey);

            assertEqualArrayBuffers(aliceShared, bobShared);
        });

        it("produces a 32-byte shared secret", async function () {
            const alice = await curve.generateKeyPair();
            const bob = await curve.generateKeyPair();

            const shared = await curve.calculateAgreement(bob.pubKey, alice.privKey);
            assert.instanceOf(shared, ArrayBuffer);
            assert.strictEqual(shared.byteLength, 32);
        });

        it("throws for invalid public key format (wrong length)", async function () {
            const kp = await curve.generateKeyPair();
            const badPub = new ArrayBuffer(10);
            let error;
            try {
                await curve.calculateAgreement(badPub, kp.privKey);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid public key");
        });

        // Canonical small-order Curve25519 u-coordinates (little-endian). X25519
        // with any clamped scalar yields the all-zero shared secret for these,
        // so calculateAgreement must reject them (RFC 7748 §6.1).
        const LOW_ORDER_POINTS_HEX = [
            "0000000000000000000000000000000000000000000000000000000000000000", // 0
            "0100000000000000000000000000000000000000000000000000000000000000", // 1
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p-1
        ];

        function hexToBytes(hex: string): Uint8Array {
            const out = new Uint8Array(hex.length / 2);
            for (let i = 0; i < out.length; i++) {
                out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }

        function prefixed(u: Uint8Array): ArrayBuffer {
            const out = new Uint8Array(33);
            out[0] = 5;
            out.set(u, 1);
            return out.buffer;
        }

        LOW_ORDER_POINTS_HEX.forEach(function (hex, i) {
            it(`rejects low-order public key #${i} (all-zero shared secret)`, async function () {
                const priv = (await curve.generateKeyPair()).privKey;
                let error;
                try {
                    await curve.calculateAgreement(prefixed(hexToBytes(hex)), priv);
                } catch (e) {
                    error = e;
                }
                expect(error).to.be.an.instanceof(Error);
                assert.match((error as Error).message, /all-zero shared secret/);
            });
        });

        // The DH path requires the canonical 33-byte 0x05-prefixed
        // form; a raw 32-byte (un-prefixed) key is rejected outright rather
        // than silently coerced into a curve point.
        it("rejects a raw 32-byte (un-prefixed) public key", async function () {
            const kp = await curve.generateKeyPair();
            const raw32 = kp.pubKey.slice(1); // drop the 0x05 type prefix
            assert.strictEqual(raw32.byteLength, 32);
            let error;
            try {
                await curve.calculateAgreement(raw32, kp.privKey);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid public key");
        });

        it("still accepts a normal peer public key", async function () {
            const alice = await curve.generateKeyPair();
            const bob = await curve.generateKeyPair();
            const shared = await curve.calculateAgreement(bob.pubKey, alice.privKey);
            assert.strictEqual(shared.byteLength, 32);
        });
    });

    describe("curvePubKeyToEd25519PubKey", function () {
        it("accepts the 33-byte 0x05-prefixed form", async function () {
            const kp = await curve.generateKeyPair();
            const ed = await curve.curvePubKeyToEd25519PubKey(kp.pubKey);
            assert.strictEqual(ed.byteLength, 32);
        });

        // This conversion helper explicitly opts in to the raw 32-byte
        // form (its documented contract); both forms must yield the same key.
        it("also accepts the raw 32-byte form and agrees with the prefixed form", async function () {
            const kp = await curve.generateKeyPair();
            const fromPrefixed = await curve.curvePubKeyToEd25519PubKey(kp.pubKey);
            const fromRaw = await curve.curvePubKeyToEd25519PubKey(kp.pubKey.slice(1));
            assertEqualArrayBuffers(fromRaw, fromPrefixed);
        });
    });

    describe("calculateSignature", function () {
        it("produces a 64-byte signature", async function () {
            const kp = await curve.generateKeyPair();

            const message = new Uint8Array([1, 2, 3, 4, 5]).buffer;
            const sig = await curve.calculateSignature(kp.privKey, message);

            assert.instanceOf(sig, ArrayBuffer);
            assert.strictEqual(sig.byteLength, 64);
        });

        it("throws for undefined message", async function () {
            const kp = await curve.generateKeyPair();
            let error;
            try {
                await curve.calculateSignature(kp.privKey, undefined as unknown as ArrayBuffer);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid message");
        });
    });

    describe("verifySignature", function () {
        it("verifies a valid signature (resolves with undefined)", async function () {
            const kp = await curve.generateKeyPair();
            const message = new TextEncoder().encode("test message").buffer;

            const sig = await curve.calculateSignature(kp.privKey, message);
            const result = await curve.verifySignature(kp.pubKey, message, sig);

            assert.isUndefined(result);
        });

        it("rejects for a tampered message", async function () {
            const kp = await curve.generateKeyPair();
            const message = new TextEncoder().encode("test message").buffer;
            const badMsg = new TextEncoder().encode("bad message").buffer;
            const sig = await curve.calculateSignature(kp.privKey, message);

            let error;
            try {
                await curve.verifySignature(kp.pubKey, badMsg, sig);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid signature");
        });

        it("rejects for a tampered signature", async function () {
            const kp = await curve.generateKeyPair();
            const message = new TextEncoder().encode("test message").buffer;
            const sig = await curve.calculateSignature(kp.privKey, message);
            const badSig = new Uint8Array(sig);
            badSig[0] = (badSig[0] + 1) & 0xff;

            let error;
            try {
                await curve.verifySignature(kp.pubKey, message, badSig.buffer);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid signature");
        });

        it("throws for invalid public key format", async function () {
            const badPub = new ArrayBuffer(10);
            const msg = new ArrayBuffer(5);
            const sig = new ArrayBuffer(64);
            let error;
            try {
                await curve.verifySignature(badPub, msg, sig);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid public key");
        });

        it("throws for invalid signature length", async function () {
            const kp = await curve.generateKeyPair();
            const msg = new ArrayBuffer(5);
            const badSig = new ArrayBuffer(10);
            let error;
            try {
                await curve.verifySignature(kp.pubKey, msg, badSig);
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual((error as Error).message, "Invalid signature");
        });

        it("works correctly across many different key pairs", async function () {
            const NUM_PAIRS = 50;
            const message = new TextEncoder().encode("multi-key-pair test message").buffer;
            const keyPairs = [];

            for (let i = 0; i < NUM_PAIRS; i++) {
                keyPairs.push(await curve.generateKeyPair());
            }

            for (let i = 0; i < NUM_PAIRS; i++) {
                const sig = await curve.calculateSignature(keyPairs[i].privKey, message);
                assert.strictEqual(sig.byteLength, 64);

                await curve.verifySignature(keyPairs[i].pubKey, message, sig);

                for (let j = 0; j < NUM_PAIRS; j++) {
                    if (j === i) continue;
                    try {
                        await curve.verifySignature(keyPairs[j].pubKey, message, sig);
                        assert.fail(`Signature from key ${i} should not verify with key ${j}`);
                    } catch (err) {
                        if ((err as Error).message !== "Invalid signature") {
                            throw err as Error;
                        }
                    }
                }
            }
        });
    });
});

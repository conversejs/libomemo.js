import { assert, expect } from "chai";
import { SessionBuilder, SessionCipher, OMEMOAddress, KeyHelper, util } from "../src/index.js";
import { SessionRecord } from "../src/session/record.js";
import { generateIdentity, generatePreKeyBundle, assertEqualArrayBuffers } from "./utils.js";
import SignalProtocolStore from "./InMemorySignalProtocolStore.js";

describe("SessionBuilder", function () {
    this.timeout(5000);

    const ALICE_ADDRESS = new OMEMOAddress("+14151111111", 1);
    const BOB_ADDRESS = new OMEMOAddress("+14152222222", 1);

    describe("basic prekey v3", function () {
        const aliceStore = new SignalProtocolStore();

        const bobStore = new SignalProtocolStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        before(async function () {
            await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)]);
            const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            await builder.processPreKey(preKeyBundle);
        });

        const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre");
        const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        it("creates a session", async function () {
            const record = await aliceStore.loadSession(BOB_ADDRESS.toString());
            assert.isDefined(record);
            const sessionRecord = SessionRecord.deserialize(record);
            assert.isTrue(sessionRecord.haveOpenSession());
            assert.isDefined(sessionRecord.getOpenSession());
        });

        it("the session can encrypt", async function () {
            const ciphertext = await aliceSessionCipher.encrypt(originalMessage);
            assert.strictEqual(ciphertext.type, 3); // PREKEY_BUNDLE
            const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(
                ciphertext.body,
                "binary"
            );
            assertEqualArrayBuffers(plaintext, originalMessage);
        });

        it("the session can decrypt", async function () {
            const ciphertext = await bobSessionCipher.encrypt(originalMessage);
            const plaintext = await aliceSessionCipher.decryptWhisperMessage(
                ciphertext.body,
                "binary"
            );
            assertEqualArrayBuffers(plaintext, originalMessage);
        });

        it("accepts a new preKey with the same identity", async function () {
            const preKeyBundle = await generatePreKeyBundle(
                bobStore,
                bobPreKeyId + 1,
                bobSignedKeyId + 1
            );
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            await builder.processPreKey(preKeyBundle);
            const record = await aliceStore.loadSession(BOB_ADDRESS.toString());
            assert.isDefined(record);
            const sessionRecord = SessionRecord.deserialize(record);
            assert.isTrue(sessionRecord.haveOpenSession());
            assert.isDefined(sessionRecord.getOpenSession());
        });

        it("rejects untrusted identity keys", async function () {
            const newIdentity = await KeyHelper.generateIdentityKeyPair();
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);

            let error;
            try {
                await builder.processPreKey({
                    identityKey: newIdentity.pubKey,
                    registrationId: 12356,
                });
            } catch (e) {
                error = e;
            }

            expect(error).to.be.an.instanceof(Error);
            assert.equal(error.message, "Identity key changed");
        });
    });

    describe("basic v3 NO PREKEY", function () {
        const aliceStore = new SignalProtocolStore();

        const bobStore = new SignalProtocolStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        before(async function () {
            await Promise.all([generateIdentity(aliceStore), generateIdentity(bobStore)]);
            const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
            delete preKeyBundle.preKey;
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            await builder.processPreKey(preKeyBundle);
        });

        const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre");
        const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
        const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        it("creates a session", async function () {
            const record = await aliceStore.loadSession(BOB_ADDRESS.toString());
            assert.isDefined(record);
            const sessionRecord = SessionRecord.deserialize(record);
            assert.isTrue(sessionRecord.haveOpenSession());
            assert.isDefined(sessionRecord.getOpenSession());
        });

        it("the session can encrypt", async function () {
            const ciphertext = await aliceSessionCipher.encrypt(originalMessage);
            assert.strictEqual(ciphertext.type, 3); // PREKEY_BUNDLE

            const plaintext = await bobSessionCipher.decryptPreKeyWhisperMessage(
                ciphertext.body,
                "binary"
            );
            assertEqualArrayBuffers(plaintext, originalMessage);
        });

        it("the session can decrypt", async function () {
            const ciphertext = await bobSessionCipher.encrypt(originalMessage);
            const plaintext = await aliceSessionCipher.decryptWhisperMessage(
                ciphertext.body,
                "binary"
            );
            assertEqualArrayBuffers(plaintext, originalMessage);
        });

        it("accepts a new preKey with the same identity", async function () {
            const preKeyBundle = await generatePreKeyBundle(
                bobStore,
                bobPreKeyId + 1,
                bobSignedKeyId + 1
            );
            delete preKeyBundle.preKey;
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            await builder.processPreKey(preKeyBundle);
            const record = await aliceStore.loadSession(BOB_ADDRESS.toString());
            assert.isDefined(record);
            const sessionRecord = SessionRecord.deserialize(record);
            assert.isTrue(sessionRecord.haveOpenSession());
            assert.isDefined(sessionRecord.getOpenSession());
        });

        it("rejects untrusted identity keys", async function () {
            const newIdentity = await KeyHelper.generateIdentityKeyPair();
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            let error;
            try {
                await builder.processPreKey({
                    identityKey: newIdentity.pubKey,
                    registrationId: 12356,
                });
            } catch (e) {
                error = e;
            }
            expect(error).to.be.an.instanceof(Error);
            assert.strictEqual(error.message, "Identity key changed");
        });
    });
});

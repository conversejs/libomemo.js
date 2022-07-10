/* global SignalProtocolStore, assertEqualArrayBuffers, before, generateIdentity, generatePreKeyBundle */


describe('SessionBuilder', function() {
    this.timeout(5000);

    const { assert } = chai;
    const { util, SignalProtocolAddress, KeyHelper } = libsignal;

    const ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
    const BOB_ADDRESS   = new SignalProtocolAddress("+14152222222", 1);

    describe("basic prekey v3", function() {
        const aliceStore = new SignalProtocolStore();

        const bobStore = new SignalProtocolStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        before(function(done) {
            Promise.all([
                generateIdentity(aliceStore),
                generateIdentity(bobStore),
            ]).then(function() {
                return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
            }).then(function(preKeyBundle) {
                const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
                return builder.processPreKey(preKeyBundle).then(function() {
                    done();
                });
            }).catch(done);
        });

        const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre");
        const aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS);
        const bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);

        it('creates a session', function() {
            return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function(record) {
                assert.isDefined(record);
                const sessionRecord = Internal.SessionRecord.deserialize(record);
                assert.isTrue(sessionRecord.haveOpenSession());
                assert.isDefined(sessionRecord.getOpenSession());
            });
        });

        it('the session can encrypt', function(done) {
            aliceSessionCipher.encrypt(originalMessage).then(function(ciphertext) {

                assert.strictEqual(ciphertext.type, 3); // PREKEY_BUNDLE

                return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary');

            }).then(function(plaintext) {

                assertEqualArrayBuffers(plaintext, originalMessage);

            }).then(done, done);
        });

        it('the session can decrypt', function(done) {
            bobSessionCipher.encrypt(originalMessage).then(function(ciphertext) {

                return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary');

            }).then(function(plaintext) {

                assertEqualArrayBuffers(plaintext, originalMessage);

            }).then(done, done);
        });

        it('accepts a new preKey with the same identity', function(done) {
            generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1).then(function(preKeyBundle) {
                const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
                return builder.processPreKey(preKeyBundle).then(function() {
                    return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function(record) {
                        assert.isDefined(record);
                        const sessionRecord = Internal.SessionRecord.deserialize(record);
                        assert.isTrue(sessionRecord.haveOpenSession());
                        assert.isDefined(sessionRecord.getOpenSession());
                        done();
                    });
                });
            }).catch(done);
        });

        it('rejects untrusted identity keys', function(done) {
            KeyHelper.generateIdentityKeyPair().then(function(newIdentity) {
                const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
                return builder.processPreKey({
                    identityKey: newIdentity.pubKey,
                    registrationId : 12356
                }).then(function() {
                    assert.fail('should not be trusted');
                }).catch(function(e) {
                    assert.strictEqual(e.message, 'Identity key changed');
                    done();
                }).catch(done);
            });
        });
    });

    describe("basic v3 NO PREKEY", function() {
        const aliceStore = new SignalProtocolStore();

        const bobStore = new SignalProtocolStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        before(function(done) {
            Promise.all([
                generateIdentity(aliceStore),
                generateIdentity(bobStore),
            ]).then(function() {
                return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
            }).then(function(preKeyBundle) {
                delete preKeyBundle.preKey;
                const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
                return builder.processPreKey(preKeyBundle).then(function() {
                    done();
                });
            }).catch(done);
        });

        const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre");
        const aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS);
        const bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);

        it('creates a session', function() {
            return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function(record) {
                assert.isDefined(record);
                const sessionRecord = Internal.SessionRecord.deserialize(record);
                assert.isTrue(sessionRecord.haveOpenSession());
                assert.isDefined(sessionRecord.getOpenSession());
            });
        });

        it('the session can encrypt', function(done) {
            aliceSessionCipher.encrypt(originalMessage).then(function(ciphertext) {

                assert.strictEqual(ciphertext.type, 3); // PREKEY_BUNDLE

                return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary');

            }).then(function(plaintext) {

                assertEqualArrayBuffers(plaintext, originalMessage);

            }).then(done, done);
        });

        it('the session can decrypt', function(done) {
            bobSessionCipher.encrypt(originalMessage).then(function(ciphertext) {

                return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary');

            }).then(function(plaintext) {

                assertEqualArrayBuffers(plaintext, originalMessage);

            }).then(done, done);
        });

        it('accepts a new preKey with the same identity', function(done) {
            generatePreKeyBundle(bobStore, bobPreKeyId + 1, bobSignedKeyId + 1).then(function(preKeyBundle) {
                delete preKeyBundle.preKey;
                const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
                return builder.processPreKey(preKeyBundle).then(function() {
                    return aliceStore.loadSession(BOB_ADDRESS.toString()).then(function(record) {
                        assert.isDefined(record);
                        const sessionRecord = Internal.SessionRecord.deserialize(record);
                        assert.isTrue(sessionRecord.haveOpenSession());
                        assert.isDefined(sessionRecord.getOpenSession());
                        done();
                    });
                });
            }).catch(done);
        });

        it('rejects untrusted identity keys', function(done) {
            KeyHelper.generateIdentityKeyPair().then(function(newIdentity) {
                const builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
                return builder.processPreKey({
                    identityKey: newIdentity.pubKey,
                    registrationId : 12356
                }).then(function() {
                    assert.fail('should not be trusted');
                }).catch(function(e) {
                    assert.strictEqual(e.message, 'Identity key changed');
                    done();
                }).catch(done);
            });
        });
    });
});

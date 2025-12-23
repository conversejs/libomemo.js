/* global before, assertEqualArrayBuffers */

// eslint-disable-next-line no-unused-vars
function testIdentityKeyStore(store, registrationId, identityKey) {
    const { assert } = chai;

    describe("IdentityKeyStore", function () {
        const number = "+5558675309";
        const address = new libsignal.SignalProtocolAddress("+5558675309", 1);
        let testKey;

        before(function (done) {
            Internal.crypto
                .createKeyPair()
                .then(function (keyPair) {
                    testKey = keyPair;
                })
                .then(done, done);
        });

        describe("getLocalRegistrationId", function () {
            it("retrieves my registration id", function (done) {
                store
                    .getLocalRegistrationId()
                    .then(function (reg) {
                        assert.strictEqual(reg, registrationId);
                    })
                    .then(done, done);
            });
        });

        describe("getIdentityKeyPair", function () {
            it("retrieves my identity key", function (done) {
                store
                    .getIdentityKeyPair()
                    .then(function (key) {
                        assertEqualArrayBuffers(key.pubKey, identityKey.pubKey);
                        assertEqualArrayBuffers(key.privKey, identityKey.privKey);
                    })
                    .then(done, done);
            });
        });

        describe("saveIdentity", function () {
            it("stores identity keys", function (done) {
                store
                    .saveIdentity(address.toString(), testKey.pubKey)
                    .then(function () {
                        return store.loadIdentityKey(number).then(function (key) {
                            assertEqualArrayBuffers(key, testKey.pubKey);
                        });
                    })
                    .then(done, done);
            });
        });

        describe("isTrustedIdentity", function () {
            it("returns true if a key is trusted", function (done) {
                store.saveIdentity(address.toString(), testKey.pubKey).then(function () {
                    store
                        .isTrustedIdentity(number, testKey.pubKey)
                        .then(function (trusted) {
                            if (trusted) {
                                done();
                            } else {
                                done(new Error("Wrong value for trusted key"));
                            }
                        })
                        .catch(done);
                });
            });
            it("returns false if a key is untrusted", function (done) {
                const newIdentity = libsignal.crypto.getRandomBytes(33);
                store.saveIdentity(address.toString(), testKey.pubKey).then(function () {
                    store
                        .isTrustedIdentity(number, newIdentity)
                        .then(function (trusted) {
                            if (trusted) {
                                done(new Error("Wrong value for untrusted key"));
                            } else {
                                done();
                            }
                        })
                        .catch(done);
                });
            });
        });
    });
}

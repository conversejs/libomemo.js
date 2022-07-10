/* global before, assertEqualArrayBuffers, SignalProtocolAddress */

// eslint-disable-next-line no-unused-vars
function testPreKeyStore(store) {

    const { assert } = chai;
    const number = '+5558675309';
    let testKey;

    describe('PreKeyStore', function() {

        before(function(done) {
            Internal.crypto.createKeyPair().then(function(keyPair) {
                testKey = keyPair;
            }).then(done,done);
        });

        describe('storePreKey', function() {
            it('stores prekeys', function(done) {
                const address = new SignalProtocolAddress(number, 1);
                store.storePreKey(address.toString(), testKey).then(function() {
                    return store.loadPreKey(address.toString()).then(function(key) {
                        assertEqualArrayBuffers(key.pubKey, testKey.pubKey);
                        assertEqualArrayBuffers(key.privKey, testKey.privKey);
                    });
                }).then(done,done);
            });
        });

        describe('loadPreKey', function() {
            it('returns prekeys that exist', function(done) {
                const address = new SignalProtocolAddress(number, 1);
                store.storePreKey(address.toString(), testKey).then(function() {
                    return store.loadPreKey(address.toString()).then(function(key) {
                        assertEqualArrayBuffers(key.pubKey, testKey.pubKey);
                        assertEqualArrayBuffers(key.privKey, testKey.privKey);
                    });
                }).then(done,done);
            });
            it('returns undefined for prekeys that do not exist', function() {
                const address = new SignalProtocolAddress(number, 2);
                return store.loadPreKey(address.toString()).then(function(key) {
                    assert.isUndefined(key);
                });
            });
        });

        describe('removePreKey', function() {
            it('deletes prekeys', function(done) {
                const address = new SignalProtocolAddress(number, 2);
                before(function(done) {
                    store.storePreKey(address.toString(), testKey).then(done);
                });
                store.removePreKey(address.toString()).then(function() {
                    return store.loadPreKey(address.toString()).then(function(key) {
                        assert.isUndefined(key);
                    });
                }).then(done,done);
            });
        });
    });
}

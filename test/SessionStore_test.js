/* global before, assertEqualArrayBuffers, SignalProtocolAddress */

// eslint-disable-next-line no-unused-vars
function testSessionStore(store) {

    const { assert } = chai;

    describe('SessionStore', function() {
        const number = '+5558675309';
        const testRecord = 'an opaque string';
        describe('storeSession', function() {
            const address = new SignalProtocolAddress(number, 1);
            it('stores sessions encoded as strings', function(done) {
                store.storeSession(address.toString(), testRecord).then(function() {
                    return store.loadSession(address.toString()).then(function(record) {
                        assert.strictEqual(record, testRecord);
                    });
                }).then(done,done);
            });
            it('stores sessions encoded as array buffers', function(done) {
                const testRecord = new Uint8Array([1,2,3]).buffer;
                store.storeSession(address.toString(), testRecord).then(function() {
                    return store.loadSession(address.toString()).then(function(record) {
                        assertEqualArrayBuffers(testRecord, record);
                    });
                }).then(done,done);
            });
        });
        describe('loadSession', function() {
            it('returns sessions that exist', function(done) {
              const address = new SignalProtocolAddress(number, 1);
                const testRecord = 'an opaque string';
                store.storeSession(address.toString(), testRecord).then(function() {
                    return store.loadSession(address.toString()).then(function(record) {
                        assert.strictEqual(record, testRecord);
                    });
                }).then(done,done);
            });
            it('returns undefined for sessions that do not exist', function() {
                const address = new SignalProtocolAddress(number, 2);
                return store.loadSession(address.toString()).then(function(record) {
                    assert.isUndefined(record);
                });
            });
        });
        describe('removeSession', function() {
            it('deletes sessions', function(done) {
                const address = new SignalProtocolAddress(number, 1);
                before(function(done) {
                    store.storeSession(address.toString(), testRecord).then(done);
                });
                store.removeSession(address.toString()).then(function() {
                    return store.loadSession(address.toString()).then(function(record) {
                        assert.isUndefined(record);
                    });
                }).then(done,done);
            });
        });
        describe('removeAllSessions', function() {
            it('removes all sessions for a number', function(done) {
                const devices = [1, 2, 3].map(function(deviceId) {
                    const address = new SignalProtocolAddress(number, deviceId);
                    return address.toString();
                });
                let promise = Promise.resolve();
                devices.forEach(function(encodedNumber) {
                    promise = promise.then(function() {
                        return store.storeSession(encodedNumber, testRecord + encodedNumber);
                    });
                });
                promise.then(function() {
                    return store.removeAllSessions(number).then(function() {
                        return Promise.all(devices.map(store.loadSession.bind(store))).then(function(records) {
                            for (const i in records) {
                                if (!Object.prototype.hasOwnProperty.call(records, i)) {
                                    continue;
                                }
                                assert.isUndefined(records[i]);
                            }
                        });
                    });
                }).then(done,done);
            });
        });
    });
}

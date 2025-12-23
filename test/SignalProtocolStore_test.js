/* vim: ts=4:sw=4 */
/* global before, SignalProtocolStore, testIdentityKeyStore, testPreKeyStore, testSignedPreKeyStore, testSessionStore */

"use strict";

describe("SignalProtocolStore", function () {
    const store = new SignalProtocolStore();
    const registrationId = 1337;
    const identityKey = {
        pubKey: Internal.crypto.getRandomBytes(33),
        privKey: Internal.crypto.getRandomBytes(32),
    };
    before(function () {
        store.put("registrationId", registrationId);
        store.put("identityKey", identityKey);
    });
    testIdentityKeyStore(store, registrationId, identityKey);
    testPreKeyStore(store);
    testSignedPreKeyStore(store);
    testSessionStore(store);
});

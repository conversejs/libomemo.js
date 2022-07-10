/* global KeyHelper */

window.libsignal = {};
window.Internal = {};

/*
 * global helpers for tests
 */

// eslint-disable-next-line no-unused-vars
function assertEqualArrayBuffers(ab1, ab2) {
  chai.assert.deepEqual(new Uint8Array(ab1), new Uint8Array(ab2));
}

// eslint-disable-next-line no-unused-vars
function hexToArrayBuffer(str) {
  const ret = new ArrayBuffer(str.length / 2);
  const array = new Uint8Array(ret);
  for (let i = 0; i < str.length/2; i++) {
    array[i] = parseInt(str.substr(i*2, 2), 16);
  }
  return ret;
}

// eslint-disable-next-line no-unused-vars
function generateIdentity(store) {
    return Promise.all([
        KeyHelper.generateIdentityKeyPair(),
        KeyHelper.generateRegistrationId(),
    ]).then(function(result) {
        store.put('identityKey', result[0]);
        store.put('registrationId', result[1]);
    });
}

// eslint-disable-next-line no-unused-vars
function generatePreKeyBundle(store, preKeyId, signedPreKeyId) {
    return Promise.all([
        store.getIdentityKeyPair(),
        store.getLocalRegistrationId()
    ]).then(function(result) {
        const identity = result[0];
        const registrationId = result[1];

        return Promise.all([
            KeyHelper.generatePreKey(preKeyId),
            KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
        ]).then(function(keys) {
            const preKey = keys[0];
            const signedPreKey = keys[1];

            store.storePreKey(preKeyId, preKey.keyPair);
            store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);

            return {
                identityKey: identity.pubKey,
                registrationId : registrationId,
                preKey:  {
                    keyId     : preKeyId,
                    publicKey : preKey.keyPair.pubKey
                },
                signedPreKey: {
                    keyId     : signedPreKeyId,
                    publicKey : signedPreKey.keyPair.pubKey,
                    signature : signedPreKey.signature
                }
            };
        });
    });
}

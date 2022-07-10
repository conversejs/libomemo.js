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
  const view = new Uint8Array(str.length / 2);
  for (let i = 0; i < str.length; i += 2) {
    view[i / 2] = parseInt(str.substr(i, 2), 16);
  }
  return view.buffer;
}

// eslint-disable-next-line no-unused-vars
function hexToUint8Array(str) {
  const view = new Uint8Array(str.length / 2);
  for (let i = 0; i < str.length; i += 2) {
    view[i / 2] = parseInt(str.substr(i, 2), 16);
  }
  return view;
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

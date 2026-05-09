import { assert } from "chai";
import { KeyHelper } from "../src/KeyHelper.js";

export function assertEqualArrayBuffers(ab1, ab2) {
    assert.deepEqual(new Uint8Array(ab1), new Uint8Array(ab2));
}

export function hexToArrayBuffer(str) {
    const view = new Uint8Array(str.length / 2);
    for (let i = 0; i < str.length; i += 2) {
        view[i / 2] = parseInt(str.substr(i, 2), 16);
    }
    return view.buffer;
}

export function hexToUint8Array(str) {
    const view = new Uint8Array(str.length / 2);
    for (let i = 0; i < str.length; i += 2) {
        view[i / 2] = parseInt(str.substr(i, 2), 16);
    }
    return view;
}

export function generateIdentity(store) {
    return Promise.all([
        KeyHelper.generateIdentityKeyPair(),
        KeyHelper.generateRegistrationId(),
    ]).then(function (result) {
        store.put("identityKey", result[0]);
        store.put("registrationId", result[1]);
    });
}

export function generatePreKeyBundle(store, preKeyId, signedPreKeyId) {
    return Promise.all([store.getIdentityKeyPair(), store.getLocalRegistrationId()]).then(
        function (result) {
            const identity = result[0];
            const registrationId = result[1];

            return Promise.all([
                KeyHelper.generatePreKey(preKeyId),
                KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
            ]).then(function (keys) {
                const preKey = keys[0];
                const signedPreKey = keys[1];

                store.storePreKey(preKeyId, preKey.keyPair);
                store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);

                return {
                    identityKey: identity.pubKey,
                    registrationId: registrationId,
                    preKey: {
                        keyId: preKeyId,
                        publicKey: preKey.keyPair.pubKey,
                    },
                    signedPreKey: {
                        keyId: signedPreKeyId,
                        publicKey: signedPreKey.keyPair.pubKey,
                        signature: signedPreKey.signature,
                    },
                };
            });
        }
    );
}

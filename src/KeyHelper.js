import { internalCrypto, getRandomBytes } from "./crypto.js";

function isNonNegativeInteger(n) {
    return typeof n === "number" && n % 1 === 0 && n >= 0;
}

export const KeyHelper = {
    generateIdentityKeyPair() {
        return internalCrypto.createKeyPair();
    },

    generateRegistrationId() {
        const registrationId = new Uint16Array(getRandomBytes(2))[0];
        return registrationId & 0x3fff;
    },

    generateSignedPreKey(identityKeyPair, signedKeyId) {
        if (
            !(identityKeyPair.privKey instanceof ArrayBuffer) ||
            identityKeyPair.privKey.byteLength !== 32 ||
            !(identityKeyPair.pubKey instanceof ArrayBuffer) ||
            identityKeyPair.pubKey.byteLength !== 33
        ) {
            throw new TypeError("Invalid argument for identityKeyPair");
        }
        if (!isNonNegativeInteger(signedKeyId)) {
            throw new TypeError(`Invalid argument for signedKeyId: ${signedKeyId}`);
        }

        return internalCrypto.createKeyPair().then((keyPair) =>
            internalCrypto.Ed25519Sign(identityKeyPair.privKey, keyPair.pubKey).then((sig) => ({
                keyId: signedKeyId,
                keyPair,
                signature: sig,
            }))
        );
    },

    generatePreKey(keyId) {
        if (!isNonNegativeInteger(keyId)) {
            throw new TypeError(`Invalid argument for keyId: ${keyId}`);
        }

        return internalCrypto.createKeyPair().then((keyPair) => ({ keyId, keyPair }));
    },
};

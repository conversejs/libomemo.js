import { internalCrypto, getRandomBytes } from "./crypto";
import { isNonNegativeInteger } from "./helpers";
import { KeyId } from "./session/types";
import { KeyPair, PreKey, SignedPreKey } from "./types";

/** Helpers for generating cryptographic keys for OMEMO. */
export const KeyHelper = {
    generateIdentityKeyPair(): Promise<KeyPair> {
        return internalCrypto.createKeyPair();
    },

    generateRegistrationId(): number {
        const registrationId = new Uint16Array(getRandomBytes(2))[0];
        return registrationId & 0x3fff;
    },

    async generateSignedPreKey(
        identityKeyPair: KeyPair,
        signedKeyId: number
    ): Promise<SignedPreKey> {
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

        const keyPair = await internalCrypto.createKeyPair();
        const sig = await internalCrypto.Ed25519Sign(identityKeyPair.privKey, keyPair.pubKey);
        return {
            keyId: signedKeyId,
            keyPair,
            signature: sig,
        };
    },

    async generatePreKey(keyId: KeyId): Promise<PreKey> {
        if (!isNonNegativeInteger(keyId)) {
            throw new TypeError(`Invalid argument for keyId: ${keyId}`);
        }

        return {
            keyId,
            keyPair: await internalCrypto.createKeyPair(),
        };
    },
};

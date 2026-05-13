import { assert } from "chai";
import { KeyHelper } from "../src/key-helper";
import { OMEMOStore, PreKeyBundle } from "../src/session/types";
import { KeyPair } from "../src/types";

export function assertEqualArrayBuffers(ab1: ArrayBuffer, ab2: ArrayBuffer): void {
    assert.deepEqual(new Uint8Array(ab1), new Uint8Array(ab2));
}

export function hexToArrayBuffer(str: string): ArrayBuffer {
    const view = new Uint8Array(str.length / 2);
    for (let i = 0; i < str.length; i += 2) {
        view[i / 2] = parseInt(str.substring(i, i + 2), 16);
    }
    return view.buffer;
}

export function hexToUint8Array(str: string): Uint8Array {
    const view = new Uint8Array(str.length / 2);
    for (let i = 0; i < str.length; i += 2) {
        view[i / 2] = parseInt(str.substring(i, i + 2), 16);
    }
    return view;
}

export async function generateIdentity(store: OMEMOStore): Promise<void> {
    const result = await Promise.all([
        KeyHelper.generateIdentityKeyPair(),
        KeyHelper.generateRegistrationId(),
    ]);
    store.put("identityKey", result[0]);
    store.put("registrationId", result[1]);
}

export async function generatePreKeyBundle(
    store: OMEMOStore,
    preKeyId: number,
    signedPreKeyId: number
): Promise<PreKeyBundle> {
    const result = await Promise.all([store.getIdentityKeyPair(), store.getLocalRegistrationId()]);
    const identity = result[0] as KeyPair;
    const registrationId = result[1] as number;

    const [preKey, signedPreKey] = await Promise.all([
        KeyHelper.generatePreKey(preKeyId),
        KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
    ]);

    await store.storePreKey(preKeyId, preKey.keyPair);
    await store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);

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
}

import { Curve25519 } from "./curve";
import { util } from "./helpers";
import { InternalCryptoInterface, KeyPair } from "./types";

const webCrypto = globalThis.crypto;

if (!webCrypto || !webCrypto.subtle || typeof webCrypto.getRandomValues !== "function") {
    throw new Error("WebCrypto not found");
}

export function getRandomBytes(size: number): ArrayBuffer {
    const array = new Uint8Array(size);
    webCrypto.getRandomValues(array);
    return array.buffer;
}

export async function encrypt(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv: ArrayBuffer
): Promise<ArrayBuffer> {
    const algo = { name: "AES-CBC" } as const;
    const importedKey = await webCrypto.subtle.importKey("raw", key, algo, false, ["encrypt"]);
    return webCrypto.subtle.encrypt({ ...algo, iv: new Uint8Array(iv) }, importedKey, data);
}

export async function decrypt(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv: ArrayBuffer
): Promise<ArrayBuffer> {
    const algo = { name: "AES-CBC" } as const;
    const importedKey = await webCrypto.subtle.importKey("raw", key, algo, false, ["decrypt"]);
    return webCrypto.subtle.decrypt({ ...algo, iv: new Uint8Array(iv) }, importedKey, data);
}

export async function sign(key: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
    const importedKey = await webCrypto.subtle.importKey(
        "raw",
        key,
        { name: "HMAC", hash: { name: "SHA-256" } },
        false,
        ["sign"]
    );
    return webCrypto.subtle.sign({ name: "HMAC", hash: "SHA-256" }, importedKey, data);
}

export function hash(data: ArrayBuffer): Promise<ArrayBuffer> {
    return webCrypto.subtle.digest({ name: "SHA-512" }, data);
}

export async function HKDFInternal(
    input: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer
): Promise<ArrayBuffer[]> {
    const PRK = await sign(salt, input);
    const infoBuffer = new ArrayBuffer(info.byteLength + 1 + 32);
    const infoArray = new Uint8Array(infoBuffer);

    infoArray.set(new Uint8Array(info), 32);
    infoArray[infoArray.length - 1] = 1;

    const T1 = await sign(PRK, infoBuffer.slice(32));
    infoArray.set(new Uint8Array(T1));
    infoArray[infoArray.length - 1] = 2;

    const T2 = await sign(PRK, infoBuffer);
    infoArray.set(new Uint8Array(T2));
    infoArray[infoArray.length - 1] = 3;

    const T3 = await sign(PRK, infoBuffer);

    return [T1, T2, T3];
}

export function HKDF(
    input: ArrayBuffer,
    salt: ArrayBuffer,
    info: ArrayBuffer | string
): Promise<ArrayBuffer[]> {
    if (salt.byteLength !== 32) {
        throw new Error("Got salt of incorrect length");
    }
    const infoBuffer = typeof info === "string" ? util.toArrayBuffer(info)! : info;
    return HKDFInternal(input, salt, infoBuffer);
}

export async function verifyMAC(
    data: ArrayBuffer,
    key: ArrayBuffer,
    mac: ArrayBuffer,
    length: number
): Promise<void> {
    const calculatedMac = await sign(key, data);
    if (mac.byteLength !== length || calculatedMac.byteLength < length) {
        throw new Error("Bad MAC length");
    }

    const a = new Uint8Array(calculatedMac);
    const b = new Uint8Array(mac);
    let result = 0;
    for (let i = 0; i < mac.byteLength; ++i) {
        result |= a[i] ^ b[i];
    }
    if (result !== 0) {
        throw new Error("Bad MAC");
    }
}

export const internalCrypto: InternalCryptoInterface = {
    async createKeyPair(privKey?: ArrayBuffer): Promise<KeyPair> {
        if (privKey === undefined) {
            privKey = getRandomBytes(32);
        }
        const curve = new Curve25519();
        return await curve.createKeyPair(privKey);
    },

    async ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        const curve = new Curve25519();
        return await curve.ECDHE(pubKey, privKey);
    },

    async Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        const curve = new Curve25519();
        return await curve.Ed25519Sign(privKey, message);
    },

    async Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void> {
        const curve = new Curve25519();
        return await curve.verifySignature(pubKey, msg, sig);
    },
};

export const createKeyPair = (privKey?: ArrayBuffer): Promise<KeyPair> =>
    internalCrypto.createKeyPair(privKey);
export const ECDHE = (pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> =>
    internalCrypto.ECDHE(pubKey, privKey);
export const Ed25519Sign = (privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> =>
    internalCrypto.Ed25519Sign(privKey, message);
export const Ed25519Verify = (
    pubKey: ArrayBuffer,
    msg: ArrayBuffer,
    sig: ArrayBuffer
): Promise<void> => internalCrypto.Ed25519Verify(pubKey, msg, sig);

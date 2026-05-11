import { curve25519Async } from "./Curve.js";
import { util } from "./helpers.js";

const webCrypto = globalThis.crypto;

if (!webCrypto || !webCrypto.subtle || typeof webCrypto.getRandomValues !== "function") {
    throw new Error("WebCrypto not found");
}

export function getRandomBytes(size) {
    const array = new Uint8Array(size);
    webCrypto.getRandomValues(array);
    return array.buffer;
}

export async function encrypt(key, data, iv) {
    const algo = { name: "AES-CBC" };
    const importedKey = await webCrypto.subtle.importKey("raw", key, algo, false, ["encrypt"]);
    return webCrypto.subtle.encrypt({ ...algo, iv: new Uint8Array(iv) }, importedKey, data);
}

export async function decrypt(key, data, iv) {
    const algo = { name: "AES-CBC" };
    const importedKey = await webCrypto.subtle.importKey("raw", key, algo, false, ["decrypt"]);
    return webCrypto.subtle.decrypt({ ...algo, iv: new Uint8Array(iv) }, importedKey, data);
}

export async function sign(key, data) {
    const importedKey = await webCrypto.subtle.importKey(
        "raw",
        key,
        { name: "HMAC", hash: { name: "SHA-256" } },
        false,
        ["sign"]
    );
    return webCrypto.subtle.sign({ name: "HMAC", hash: "SHA-256" }, importedKey, data);
}

export function hash(data) {
    return webCrypto.subtle.digest({ name: "SHA-512" }, data);
}

export async function HKDFInternal(input, salt, info) {
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

export function HKDF(input, salt, info) {
    if (salt.byteLength !== 32) {
        throw new Error("Got salt of incorrect length");
    }
    const infoBuffer = typeof info === "string" ? util.toArrayBuffer(info) : info;
    return HKDFInternal(input, salt, infoBuffer);
}

export async function verifyMAC(data, key, mac, length) {
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

// Mutable object for curve operations that tests may override (e.g. signal protocol
// test vectors inject predetermined keys by replacing Internal.crypto.createKeyPair).
// Internal code calls methods on this object so replacements propagate to all callers.
export const internalCrypto = {
    async createKeyPair(privKey) {
        if (privKey === undefined) {
            privKey = getRandomBytes(32);
        }
        const curve = await curve25519Async;
        return curve.createKeyPair(privKey);
    },

    async ECDHE(pubKey, privKey) {
        const curve = await curve25519Async;
        return curve.ECDHE(pubKey, privKey);
    },

    async Ed25519Sign(privKey, message) {
        const curve = await curve25519Async;
        return curve.Ed25519Sign(privKey, message);
    },

    async Ed25519Verify(pubKey, msg, sig) {
        const curve = await curve25519Async;
        return curve.Ed25519Verify(pubKey, msg, sig);
    },
};

// Named exports for direct importers
export const createKeyPair = (privKey) => internalCrypto.createKeyPair(privKey);
export const ECDHE = (pubKey, privKey) => internalCrypto.ECDHE(pubKey, privKey);
export const Ed25519Sign = (privKey, message) => internalCrypto.Ed25519Sign(privKey, message);
export const Ed25519Verify = (pubKey, msg, sig) => internalCrypto.Ed25519Verify(pubKey, msg, sig);

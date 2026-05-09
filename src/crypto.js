/*
 * vim: ts=4:sw=4
 */

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

export function encrypt(key, data, iv) {
    return webCrypto.subtle
        .importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt"])
        .then((importedKey) =>
            webCrypto.subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(iv) }, importedKey, data)
        );
}

export function decrypt(key, data, iv) {
    return webCrypto.subtle
        .importKey("raw", key, { name: "AES-CBC" }, false, ["decrypt"])
        .then((importedKey) =>
            webCrypto.subtle.decrypt({ name: "AES-CBC", iv: new Uint8Array(iv) }, importedKey, data)
        );
}

export function sign(key, data) {
    return webCrypto.subtle
        .importKey("raw", key, { name: "HMAC", hash: { name: "SHA-256" } }, false, ["sign"])
        .then((importedKey) =>
            webCrypto.subtle.sign({ name: "HMAC", hash: "SHA-256" }, importedKey, data)
        );
}

export function hash(data) {
    return webCrypto.subtle.digest({ name: "SHA-512" }, data);
}

export function HKDFInternal(input, salt, info) {
    return sign(salt, input).then((PRK) => {
        const infoBuffer = new ArrayBuffer(info.byteLength + 1 + 32);
        const infoArray = new Uint8Array(infoBuffer);
        infoArray.set(new Uint8Array(info), 32);
        infoArray[infoArray.length - 1] = 1;
        return sign(PRK, infoBuffer.slice(32)).then((T1) => {
            infoArray.set(new Uint8Array(T1));
            infoArray[infoArray.length - 1] = 2;
            return sign(PRK, infoBuffer).then((T2) => {
                infoArray.set(new Uint8Array(T2));
                infoArray[infoArray.length - 1] = 3;
                return sign(PRK, infoBuffer).then((T3) => [T1, T2, T3]);
            });
        });
    });
}

export function HKDF(input, salt, info) {
    if (salt.byteLength !== 32) {
        throw new Error("Got salt of incorrect length");
    }
    const infoBuffer = typeof info === "string" ? util.toArrayBuffer(info) : info;
    return HKDFInternal(input, salt, infoBuffer);
}

export function verifyMAC(data, key, mac, length) {
    return sign(key, data).then((calculated_mac) => {
        if (mac.byteLength !== length || calculated_mac.byteLength < length) {
            throw new Error("Bad MAC length");
        }
        const a = new Uint8Array(calculated_mac);
        const b = new Uint8Array(mac);
        let result = 0;
        for (let i = 0; i < mac.byteLength; ++i) {
            result |= a[i] ^ b[i];
        }
        if (result !== 0) {
            throw new Error("Bad MAC");
        }
    });
}

// Mutable object for curve operations that tests may override (e.g. signal protocol
// test vectors inject predetermined keys by replacing Internal.crypto.createKeyPair).
// Internal code calls methods on this object so replacements propagate to all callers.
export const internalCrypto = {
    createKeyPair(privKey) {
        if (privKey === undefined) {
            privKey = getRandomBytes(32);
        }
        return curve25519Async.then((curve) => curve.createKeyPair(privKey));
    },
    ECDHE(pubKey, privKey) {
        return curve25519Async.then((curve) => curve.ECDHE(pubKey, privKey));
    },
    Ed25519Sign(privKey, message) {
        return curve25519Async.then((curve) => curve.Ed25519Sign(privKey, message));
    },
    Ed25519Verify(pubKey, msg, sig) {
        return curve25519Async.then((curve) => curve.Ed25519Verify(pubKey, msg, sig));
    },
};

// Named exports for direct importers
export const createKeyPair = (privKey) => internalCrypto.createKeyPair(privKey);
export const ECDHE = (pubKey, privKey) => internalCrypto.ECDHE(pubKey, privKey);
export const Ed25519Sign = (privKey, message) => internalCrypto.Ed25519Sign(privKey, message);
export const Ed25519Verify = (pubKey, msg, sig) => internalCrypto.Ed25519Verify(pubKey, msg, sig);

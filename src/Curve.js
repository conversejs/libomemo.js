import { createCurve25519, createCurve25519Async, getModule } from "./curve25519_wrapper.js";

function generateRandomBytes(size) {
    const array = new Uint8Array(size);
    globalThis.crypto.getRandomValues(array);
    return array.buffer;
}

function validatePrivKey(privKey) {
    if (!(privKey instanceof ArrayBuffer)) {
        throw new Error("Invalid private key: expected ArrayBuffer");
    }
    if (privKey.byteLength !== 32) {
        throw new Error("Invalid private key");
    }
}

function validatePubKeyFormat(pubKey) {
    if (!(pubKey instanceof ArrayBuffer)) {
        throw new Error("Invalid public key: expected ArrayBuffer");
    }
    if ((pubKey.byteLength !== 33 || new Uint8Array(pubKey)[0] !== 5) && pubKey.byteLength !== 32) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength === 33) {
        return pubKey.slice(1);
    }
    console.error(
        "WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey"
    );
    return pubKey;
}

function processKeys(raw_keys) {
    const origPub = new Uint8Array(raw_keys.pubKey);
    const pub = new Uint8Array(33);
    pub.set(origPub, 1);
    pub[0] = 5;
    return { pubKey: pub.buffer, privKey: raw_keys.privKey };
}

function wrapCurve25519(curve25519) {
    return {
        createKeyPair(privKey) {
            validatePrivKey(privKey);
            const raw_keys = curve25519.keyPair(privKey);
            if (raw_keys instanceof Promise) {
                return raw_keys.then(processKeys);
            }
            return processKeys(raw_keys);
        },
        ECDHE(pubKey, privKey) {
            pubKey = validatePubKeyFormat(pubKey);
            validatePrivKey(privKey);
            if (pubKey === undefined || pubKey.byteLength !== 32) {
                throw new Error("Invalid public key");
            }
            return curve25519.sharedSecret(pubKey, privKey);
        },
        Ed25519Sign(privKey, message) {
            validatePrivKey(privKey);
            if (message === undefined) {
                throw new Error("Invalid message");
            }
            return curve25519.sign(privKey, message);
        },
        Ed25519Verify(pubKey, msg, sig) {
            pubKey = validatePubKeyFormat(pubKey);
            if (pubKey === undefined || pubKey.byteLength !== 32) {
                throw new Error("Invalid public key");
            }
            if (msg === undefined) {
                throw new Error("Invalid message");
            }
            if (sig === undefined || sig.byteLength !== 64) {
                throw new Error("Invalid signature");
            }
            return curve25519.verify(pubKey, msg, sig);
        },
    };
}

function wrapCurve(curve) {
    return {
        generateKeyPair() {
            const privKey = generateRandomBytes(32);
            return curve.createKeyPair(privKey);
        },
        createKeyPair(privKey) {
            return curve.createKeyPair(privKey);
        },
        calculateAgreement(pubKey, privKey) {
            return curve.ECDHE(pubKey, privKey);
        },
        verifySignature(pubKey, msg, sig) {
            return curve.Ed25519Verify(pubKey, msg, sig);
        },
        calculateSignature(privKey, message) {
            return curve.Ed25519Sign(privKey, message);
        },
    };
}

const curve25519_sync = createCurve25519();

// Async curve25519 promise - resolves to wrapCurve25519 result (has createKeyPair, ECDHE, Ed25519Sign, Ed25519Verify)
const curve25519AsyncPromise = getModule().then((Module) => {
    const syncFromModule = createCurve25519(Module);
    const asyncWrapper = createCurve25519Async(syncFromModule);
    return wrapCurve25519(asyncWrapper);
});

// Full async curve promise - resolves to wrapCurve result (has generateKeyPair, calculateAgreement, etc.)
const curveAsyncPromise = curve25519AsyncPromise.then((wrapped25519) => wrapCurve(wrapped25519));

export const Curve = wrapCurve(curve25519_sync);

// Curve.async mirrors the sync API but uses the async (WASM) implementation
// Validation is done synchronously so tests using assert.throws work correctly
Curve.async = {
    async generateKeyPair() {
        const privKey = generateRandomBytes(32);
        const curve = await curve25519AsyncPromise;
        return curve.createKeyPair(privKey);
    },

    async createKeyPair(privKey) {
        validatePrivKey(privKey);
        const curve = await curve25519AsyncPromise;
        return curve.createKeyPair(privKey);
    },

    async calculateAgreement(pubKey, privKey) {
        validatePubKeyFormat(pubKey);
        validatePrivKey(privKey);
        const curve = await curve25519AsyncPromise;
        return curve.ECDHE(pubKey, privKey);
    },

    async verifySignature(pubKey, msg, sig) {
        validatePubKeyFormat(pubKey);
        if (msg === undefined) {
            throw new Error("Invalid message");
        }
        if (sig === undefined || sig.byteLength !== 64) {
            throw new Error("Invalid signature");
        }
        const curve = await curve25519AsyncPromise;
        return curve.Ed25519Verify(pubKey, msg, sig);
    },

    async calculateSignature(privKey, message) {
        validatePrivKey(privKey);
        if (message === undefined) {
            throw new Error("Invalid message");
        }
        const curve = await curve25519AsyncPromise;
        return curve.Ed25519Sign(privKey, message);
    },
};

// Export raw promises for internal use
export const curveAsync = curveAsyncPromise;
export const curve25519Async = curve25519AsyncPromise;

import { Curve25519 } from "./curve";
import { util } from "./helpers";
import { CurveBackend, InternalCryptoInterface, KeyPair } from "./types";

const webCrypto = globalThis.crypto;

if (!webCrypto || !webCrypto.subtle || typeof webCrypto.getRandomValues !== "function") {
    throw new Error("WebCrypto not found");
}

/** Generate cryptographically secure random bytes. */
export function getRandomBytes(size: number): ArrayBuffer {
    const array = new Uint8Array(size);
    webCrypto.getRandomValues(array);
    return array.buffer;
}

/** AES-CBC encryption. */
export async function encrypt(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv: ArrayBuffer
): Promise<ArrayBuffer> {
    const algo = { name: "AES-CBC" } as const;
    const importedKey = await webCrypto.subtle.importKey("raw", key, algo, false, ["encrypt"]);
    return webCrypto.subtle.encrypt({ ...algo, iv: new Uint8Array(iv) }, importedKey, data);
}

/** AES-CBC decryption. */
export async function decrypt(
    key: ArrayBuffer,
    data: ArrayBuffer,
    iv: ArrayBuffer
): Promise<ArrayBuffer> {
    const algo = { name: "AES-CBC" } as const;
    const importedKey = await webCrypto.subtle.importKey("raw", key, algo, false, ["decrypt"]);
    return webCrypto.subtle.decrypt({ ...algo, iv: new Uint8Array(iv) }, importedKey, data);
}

/** HMAC-SHA256 signing. */
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

/** SHA-512 hash. */
export function hash(data: ArrayBuffer): Promise<ArrayBuffer> {
    return webCrypto.subtle.digest({ name: "SHA-512" }, data);
}

/** HKDF key derivation producing three 32-byte keys. Internal implementation. */
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

/**
 * Runs the curve operations on the main thread via the compiled WebAssembly.
 * A single `Curve25519` instance is created lazily and reused, so we compile and
 * instantiate the wasm at most once for the lifetime of the backend (rather than
 * once per operation).
 */
class LocalCurveBackend implements CurveBackend {
    #curve: Curve25519 | undefined;

    #get(): Curve25519 {
        return (this.#curve ??= new Curve25519());
    }

    createKeyPair(privKey: ArrayBuffer): Promise<KeyPair> {
        return this.#get().createKeyPair(privKey);
    }

    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#get().ECDHE(pubKey, privKey);
    }

    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#get().Ed25519Sign(privKey, message);
    }

    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void> {
        return this.#get().verifySignature(pubKey, msg, sig);
    }

    curvePubKeyToEd25519PubKey(pubKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#get().curvePubKeyToEd25519PubKey(pubKey);
    }

    ed25519PubKeyToCurvePubKey(edPubKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#get().ed25519PubKeyToCurvePubKey(edPubKey);
    }
}

// The default backend runs on the main thread. `startWorker()` swaps in a
// worker-backed one (see curve25519_worker_manager.ts); `stopWorker()` reverts.
const localBackend: CurveBackend = new LocalCurveBackend();
let activeBackend: CurveBackend = localBackend;

/** Route curve operations through `backend` (used by `startWorker`). */
export function setCurveBackend(backend: CurveBackend): void {
    activeBackend = backend;
}

/** Revert curve operations to the main-thread backend (used by `stopWorker`). */
export function resetCurveBackend(): void {
    activeBackend = localBackend;
}

/**
 * The main-thread backend. In the default build it runs the bundled wasm; in the
 * `worker-client` build it is a stub whose methods throw. A worker backend uses it
 * as its fallback target, so worker failures degrade to local wasm (default build)
 * or to a clear error (worker-client build).
 */
export function getLocalCurveBackend(): CurveBackend {
    return localBackend;
}

export const internalCrypto: InternalCryptoInterface = {
    createKeyPair(privKey?: ArrayBuffer): Promise<KeyPair> {
        return activeBackend.createKeyPair(privKey ?? getRandomBytes(32));
    },
    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        return activeBackend.ECDHE(pubKey, privKey);
    },
    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        return activeBackend.Ed25519Sign(privKey, message);
    },
    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void> {
        return activeBackend.Ed25519Verify(pubKey, msg, sig);
    },
    curvePubKeyToEd25519PubKey(pubKey: ArrayBuffer): Promise<ArrayBuffer> {
        return activeBackend.curvePubKeyToEd25519PubKey(pubKey);
    },
    ed25519PubKeyToCurvePubKey(edPubKey: ArrayBuffer): Promise<ArrayBuffer> {
        return activeBackend.ed25519PubKeyToCurvePubKey(edPubKey);
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
export const curvePubKeyToEd25519PubKey = (pubKey: ArrayBuffer): Promise<ArrayBuffer> =>
    internalCrypto.curvePubKeyToEd25519PubKey(pubKey);
export const ed25519PubKeyToCurvePubKey = (edPubKey: ArrayBuffer): Promise<ArrayBuffer> =>
    internalCrypto.ed25519PubKeyToCurvePubKey(edPubKey);

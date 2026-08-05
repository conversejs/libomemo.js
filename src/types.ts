export enum ChainType {
    SENDING = 1,
    RECEIVING = 2,
}

export enum BaseKeyType {
    OURS = 1,
    THEIRS = 2,
}

export interface KeyPair {
    pubKey: ArrayBuffer;
    privKey: ArrayBuffer;
}

export type PreKey = {
    keyId: number;
    keyPair: KeyPair;
};

export type PublicPreKey = {
    publicKey?: ArrayBuffer;
    keyId: number;
};

export interface SignedPreKey {
    keyId: number;
    keyPair: KeyPair;
    signature: ArrayBuffer;
}

export interface InternalCryptoInterface {
    createKeyPair(privKey?: ArrayBuffer): Promise<KeyPair>;
    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer>;
    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer>;
    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void>;
    curvePubKeyToEd25519PubKey(pubKey: ArrayBuffer): Promise<ArrayBuffer>;
    ed25519PubKeyToCurvePubKey(edPubKey: ArrayBuffer): Promise<ArrayBuffer>;
}

/**
 * The curve operations a backend must implement so `internalCrypto` can run them
 * either on the main thread (local WebAssembly) or off it (a Web Worker).
 *
 * The `internalCrypto` layer fills defaults (e.g. generates the private key for a keypair)
 * before delegating, so no backend needs its own RNG and the two backends stay interchangeable.
 */

/**
 * Where curve operations are running, reported to `startWorker`'s `onStatusChange`
 * whenever that changes.
 */
export interface WorkerStatus {
    offloaded: boolean; // True while operations run in the worker
    error?: Error; // Why offloading stopped. Present only when `offloaded` is false
}

export interface StartWorkerOptions {
    /**
     * Per-operation reply timeout in milliseconds (default 10000). Pass 0 to
     * disable the timeout.
     */
    timeout?: number;
    /**
     * Called when operations start or stop running in the worker. Edge-triggered:
     * it fires on a change, not per operation, and not for `stopWorker()`, which
     * the caller already knows about. Throwing from it is contained and ignored.
     */
    onStatusChange?: (status: WorkerStatus) => void;
}

export interface CurveBackend {
    createKeyPair(privKey: ArrayBuffer): Promise<KeyPair>;
    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer>;
    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer>;
    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void>;
    curvePubKeyToEd25519PubKey(pubKey: ArrayBuffer): Promise<ArrayBuffer>;
    ed25519PubKeyToCurvePubKey(edPubKey: ArrayBuffer): Promise<ArrayBuffer>;
}

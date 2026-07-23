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
export interface CurveBackend {
    createKeyPair(privKey: ArrayBuffer): Promise<KeyPair>;
    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer>;
    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer>;
    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void>;
    curvePubKeyToEd25519PubKey(pubKey: ArrayBuffer): Promise<ArrayBuffer>;
    ed25519PubKeyToCurvePubKey(edPubKey: ArrayBuffer): Promise<ArrayBuffer>;
}

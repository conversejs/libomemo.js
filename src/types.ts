export type JSONValue =
    | string
    | number
    | boolean
    | null
    | { [key: string]: JSONValue }
    | JSONValue[];

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

export interface PreKey {
    keyId: number;
    keyPair: KeyPair;
}

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
}

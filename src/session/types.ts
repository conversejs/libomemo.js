import { BaseKeyType, ChainType, Key, KeyPair } from "../types";

export type JSONValue =
    | string
    | number
    | boolean
    | null
    | { [key: string]: JSONValue }
    | JSONValue[];

export enum Direction {
    SENDING = 1,
    RECEIVING = 2,
}

export type Chain = {
    messageKeys: Record<number, ArrayBuffer>;
    chainKey: { counter: number; key?: ArrayBuffer };
    chainType?: ChainType;
};

export interface EncryptResult {
    type: number;
    body: string;
    registrationId: number;
}

interface IndexInfo {
    baseKey?: Key;
    baseKeyType?: BaseKeyType;
    closed: number;
    remoteIdentityKey: Key;
}

interface RatchetState {
    rootKey: ArrayBuffer;
    lastRemoteEphemeralKey: ArrayBuffer;
    previousCounter: number;
    ephemeralKeyPair: KeyPair;
}

interface OldRatchetEntry {
    added: number;
    ephemeralKey: ArrayBuffer;
}

interface PendingPreKey {
    signedKeyId: number;
    baseKey: ArrayBuffer;
    preKeyId?: number;
}

export interface PreKeyBundle {
    identityKey: ArrayBuffer;
    signedPreKey: {
        publicKey: ArrayBuffer;
        signature: ArrayBuffer;
        keyId: number;
    };
    preKey?: {
        publicKey: ArrayBuffer;
        keyId: number;
    };
    registrationId: number;
}

export type SessionState = {
    registrationId: number;
    currentRatchet: RatchetState;
    indexInfo: IndexInfo;
    oldRatchetList: OldRatchetEntry[];
    pendingPreKey?: PendingPreKey;
    [ephemeralKey: string]: unknown;
};

export interface MixedSessionState {
    registrationId: number;
    currentRatchet: {
        rootKey: Key;
        lastRemoteEphemeralKey: Key;
        previousCounter: number;
        ephemeralKeyPair: { pubKey: Key; privKey: Key };
    };
    indexInfo: {
        baseKey?: Key;
        baseKeyType?: BaseKeyType;
        closed: number;
        remoteIdentityKey: Key;
    };
    oldRatchetList: { added: number; ephemeralKey: Key }[];
    pendingPreKey?: { signedKeyId: number; baseKey: Key; preKeyId?: number };
    [ephemeralKey: string]: unknown;
}

export interface SerializableSessionState {
    registrationId: number;
    currentRatchet: {
        rootKey: string;
        lastRemoteEphemeralKey: string;
        previousCounter: number;
        ephemeralKeyPair: { pubKey: string; privKey: string };
    };
    indexInfo: {
        baseKey?: string;
        baseKeyType?: BaseKeyType;
        closed: number;
        remoteIdentityKey: string;
    };
    oldRatchetList: { added: number; ephemeralKey: string }[];
    pendingPreKey?: { signedKeyId: number; baseKey: string; preKeyId?: number };
    [ephemeralKey: string]: unknown;
}

export interface SessionRecordData {
    sessions: Record<string, SerializableSessionState>;
    version: string;
    registrationId?: number;
}

export interface Migration {
    version: string;
    migrate(data: SessionRecordData): void;
}

type KeyPairWrapper = { keyPair: KeyPair };

export type KeyId = number | string;

export interface OMEMOStore {
    store: Record<string, unknown>;

    put(key: string, value: unknown): void;
    get<T = unknown>(key: string, defaultValue?: T): T | undefined;
    remove(key: string): void;

    isTrustedIdentity(
        name: string,
        identityKey: ArrayBuffer,
        direction: Direction
    ): Promise<boolean> | boolean;
    loadIdentityKey(name: string): Promise<ArrayBuffer | undefined> | ArrayBuffer | undefined;
    saveIdentity(name: string, identityKey: Key): Promise<boolean> | boolean;

    loadPreKey(keyId: KeyId): Promise<KeyPairWrapper | undefined>;
    storePreKey(keyId: KeyId, keyPair: KeyPair): Promise<void> | void;
    removePreKey(keyId: KeyId): Promise<void> | void;

    loadSignedPreKey(
        keyId: number
    ): Promise<KeyPairWrapper | undefined> | KeyPairWrapper | undefined;
    storeSignedPreKey(keyId: KeyId, keyPair: KeyPair): Promise<void> | void;
    removeSignedPreKey(keyId: KeyId): Promise<void> | void;

    loadSession(address: string): Promise<string | undefined> | string | undefined;
    removeAllSessions(identifier: string): Promise<void> | void;
    removeSession(identifier: string): Promise<void> | void;
    storeSession(address: string, record: string): Promise<void> | void;

    getIdentityKeyPair(): Promise<KeyPair | undefined> | KeyPair | undefined;
    getLocalRegistrationId(): Promise<number | undefined> | number | undefined;
}

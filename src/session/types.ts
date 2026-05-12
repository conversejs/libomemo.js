import { BaseKeyType, JSONValue, KeyPair } from "../types";

export interface EncryptResult {
    type: number;
    body: string;
    registrationId: number;
}

interface IndexInfo {
    remoteIdentityKey: ArrayBuffer;
    closed: number;
    baseKey?: ArrayBuffer;
    baseKeyType?: BaseKeyType;
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

export interface SessionState {
    registrationId: number;
    currentRatchet: RatchetState;
    indexInfo: IndexInfo;
    oldRatchetList: OldRatchetEntry[];
    pendingPreKey?: PendingPreKey;
    [ephemeralKey: string]: unknown;
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

export interface SerializableSessionState {
    registrationId: number;
    currentRatchet: {
        rootKey: string;
        lastRemoteEphemeralKey: string;
        previousCounter: number;
        ephemeralKeyPair: { pubKey: string; privKey: string };
    };
    indexInfo: {
        remoteIdentityKey: string;
        closed: number;
        baseKey?: string;
        baseKeyType?: BaseKeyType;
    };
    oldRatchetList: { added: number; ephemeralKey: string }[];
    pendingPreKey?: { signedKeyId: number; baseKey: string; preKeyId?: number };
    [ephemeralKey: string]: JSONValue | undefined;
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

export interface StorageDirection {
    SENDING: string;
    RECEIVING: string;
}

export interface SignalProtocolStore {
    Direction: StorageDirection;
    isTrustedIdentity(name: string, identityKey: ArrayBuffer, direction: string): Promise<boolean>;
    getIdentityKeyPair(): Promise<KeyPair>;
    getLocalRegistrationId(): Promise<number>;
    loadSession(address: string): Promise<string | undefined>;
    storeSession(address: string, data: string): Promise<void>;
    saveIdentity(name: string, identityKey: ArrayBuffer): Promise<void>;
    loadPreKey(keyId: number): Promise<{ keyPair: KeyPair } | undefined>;
    loadSignedPreKey(keyId: number): Promise<{ keyPair: KeyPair } | undefined>;
    removePreKey(keyId: number): Promise<void>;
}

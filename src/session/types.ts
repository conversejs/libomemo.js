import { BaseKeyType, ChainType, KeyPair, PublicPreKey } from "../types";

/**
 * The OMEMO protocol versions this library supports, identified by their XML
 * namespace.
 *
 * - `"eu.siacs.conversations.axolotl"` — XEP-0384 v0.3.0 (the libsignal "v3"
 *   wire format).
 * - `"urn:xmpp:omemo:2"` — the latest XEP-0384.
 */
export type OMEMOVersion = "eu.siacs.conversations.axolotl" | "urn:xmpp:omemo:2";

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
    registrationId?: number;
    /**
     * omemo:2 only: whether `body` is an `OMEMOKeyExchange` (`true`) or a plain
     * `OMEMOAuthenticatedMessage` (`false`). Consumers place this in the `kex`
     * attribute of the `<key>` element.
     */
    kex?: boolean;
}

export interface RatchetState {
    rootKey: ArrayBuffer;
    lastRemoteEphemeralKey: ArrayBuffer;
    previousCounter: number;
    ephemeralKeyPair: KeyPair;
}

interface OldRatchetEntry {
    added: number;
    ephemeralKey: ArrayBuffer;
}

export interface PreKeyBundle {
    identityKey: ArrayBuffer;
    signedPreKey: {
        publicKey: ArrayBuffer;
        signature: ArrayBuffer;
        keyId: number;
    };
    preKey?: PublicPreKey;
    registrationId: number;
}

export type SessionState = {
    registrationId: number;
    /** The OMEMO protocol version this session speaks. Absent ⇒ legacy 0.3.0. */
    protocolVersion?: OMEMOVersion;
    /** omemo:2 session-fixed associated data (`IK_A ‖ IK_B`, Ed25519). */
    ad?: ArrayBuffer;
    currentRatchet: RatchetState;
    indexInfo: {
        baseKey?: ArrayBuffer;
        baseKeyType?: BaseKeyType;
        closed: number;
        /** Remote identity key, always the internal 33-byte 0x05-Curve form. */
        remoteIdentityKey: ArrayBuffer;
        /** omemo:2 only: the published 32-byte Ed25519 form, used for trust. */
        remoteIdentityKeyEd?: ArrayBuffer;
    };
    oldRatchetList: OldRatchetEntry[];
    pendingPreKey?: {
        signedKeyId: number;
        baseKey: ArrayBuffer;
        preKeyId?: number;
    };
    [ephemeralKey: string]: unknown;
};

export interface SerializedSessionState {
    registrationId: number;
    protocolVersion?: OMEMOVersion;
    ad?: string;
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
        remoteIdentityKeyEd?: string;
    };
    oldRatchetList: { added: number; ephemeralKey: string }[];
    pendingPreKey?: { signedKeyId: number; baseKey: string; preKeyId?: number };
    [ephemeralKey: string]: unknown;
}

export interface SessionRecordData {
    sessions: Record<string, SerializedSessionState>;
    version: string;
    registrationId?: number;
}

export interface Migration {
    version: string;
    migrate(data: SessionRecordData): void;
}

type KeyPairWrapper = { keyPair: KeyPair };

export interface WhisperMessageProto {
    ephemeralKey: Uint8Array;
    counter: number;
    previousCounter: number;
    ciphertext: Uint8Array;
}

export interface PreKeyWhisperMessageProto {
    registrationId: number;
    preKeyId?: number;
    signedPreKeyId: number;
    baseKey: Uint8Array;
    identityKey: Uint8Array;
    message: Uint8Array;
}

export interface OMEMOMessageProto {
    n: number;
    pn: number;
    dh_pub: Uint8Array;
    ciphertext: Uint8Array;
}

export interface OMEMOAuthenticatedMessageProto {
    mac: Uint8Array;
    message: Uint8Array;
}

export interface OMEMOKeyExchangeProto {
    pk_id: number;
    spk_id: number;
    ik: Uint8Array;
    ek: Uint8Array;
    message: OMEMOAuthenticatedMessageProto;
}

export interface IdentityKeyError extends Error {
    identityKey: ArrayBuffer;
}

export type KeyId = number | string;

/**
 * Persistent storage backend for OMEMO session state.
 *
 * Parameters named `address` accept a serialized {@link OMEMOAddress} in the
 * form `"${name}.${deviceId}"` — use `OMEMOAddress.toString()` to produce one.
 * Parameters named `jid` accept the bare JID only (no device ID suffix).
 */
export interface OMEMOStore {
    store: Record<string, unknown>;

    put(key: string, value: unknown): void;
    get<T = unknown>(key: string, defaultValue?: T): T | undefined;
    remove(key: string): void;

    isTrustedIdentity(
        address: string,
        identityKey: ArrayBuffer,
        direction: Direction
    ): Promise<boolean> | boolean;
    loadIdentityKey(address: string): Promise<ArrayBuffer | undefined> | ArrayBuffer | undefined;
    saveIdentity(address: string, identityKey: ArrayBuffer): Promise<boolean> | boolean;

    loadPreKey(keyId: KeyId): Promise<KeyPairWrapper | undefined>;
    storePreKey(keyId: KeyId, keyPair: KeyPair): Promise<void> | void;
    removePreKey(keyId: KeyId): Promise<void> | void;

    loadSignedPreKey(
        keyId: number
    ): Promise<KeyPairWrapper | undefined> | KeyPairWrapper | undefined;
    storeSignedPreKey(keyId: KeyId, keyPair: KeyPair): Promise<void> | void;
    removeSignedPreKey(keyId: KeyId): Promise<void> | void;

    loadSession(address: string): Promise<string | undefined> | string | undefined;
    removeAllSessions(jid: string): Promise<void> | void;
    removeSession(address: string): Promise<void> | void;
    storeSession(address: string, record: string): Promise<void> | void;

    getIdentityKeyPair(): Promise<KeyPair | undefined> | KeyPair | undefined;
    getLocalRegistrationId(): Promise<number | undefined> | number | undefined;
}

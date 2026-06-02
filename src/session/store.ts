import { util } from "../index";
import { type KeyPair } from "../types";
import { Direction, OMEMOStore } from "../session/types";

/**
 * Reference in-memory implementation of the OMEMOStore interface for testing and development.
 * */
export default class InMemoryStore implements OMEMOStore {
    store: Record<string | number, unknown>;

    constructor() {
        this.store = {};
    }

    getIdentityKeyPair() {
        return this.get<KeyPair>("identityKey");
    }

    getLocalRegistrationId() {
        return this.get<number>("registrationId");
    }

    put(key: string, value: unknown) {
        if (key === undefined || value === undefined || key === null || value === null)
            throw new Error("Tried to store undefined/null");
        this.store[key] = value;
    }

    get<T = unknown>(key: string, defaultValue?: T): T | undefined {
        if (key === null || key === undefined)
            throw new Error("Tried to get value for undefined/null key");
        if (key in this.store) {
            return this.store[key] as T;
        } else {
            return defaultValue;
        }
    }

    remove(key: string) {
        if (key === null || key === undefined)
            throw new Error("Tried to remove value for undefined/null key");
        delete this.store[key];
    }

    isTrustedIdentity(address: string, identityKey: ArrayBuffer, _direction: Direction) {
        if (address === null || address === undefined) {
            throw new Error("tried to check identity key for undefined/null key");
        }
        if (!(identityKey instanceof ArrayBuffer)) {
            throw new Error("Expected identityKey to be an ArrayBuffer");
        }
        const trusted = this.get<ArrayBuffer>("identityKey" + address);
        if (trusted === undefined) {
            return Promise.resolve(true);
        }
        return util.toString(identityKey) === util.toString(trusted);
    }

    loadIdentityKey(address: string) {
        if (address === null || address === undefined)
            throw new Error("Tried to get identity key for undefined/null key");
        return this.get<ArrayBuffer>("identityKey" + address);
    }

    saveIdentity(address: string, identityKey: ArrayBuffer) {
        if (address === null || address === undefined)
            throw new Error("Tried to put identity key for undefined/null key");

        const existing = this.get<ArrayBuffer>("identityKey" + address);
        this.put("identityKey" + address, identityKey);

        if (existing && util.toString(identityKey) !== util.toString(existing)) {
            return true;
        } else {
            return false;
        }
    }

    loadPreKey(keyId: number) {
        const res = this.get<KeyPair>("25519KeypreKey" + keyId);
        if (res !== undefined) {
            return Promise.resolve({ keyPair: res });
        }
        return Promise.resolve(undefined);
    }

    storePreKey(keyId: number, keyPair: KeyPair) {
        return this.put("25519KeypreKey" + keyId, keyPair);
    }

    removePreKey(keyId: number) {
        return this.remove("25519KeypreKey" + keyId);
    }

    loadSignedPreKey(keyId: number) {
        const res = this.get<KeyPair>("25519KeysignedKey" + keyId);
        if (res !== undefined) {
            return { keyPair: res };
        }
        return;
    }

    storeSignedPreKey(keyId: number, keyPair: KeyPair) {
        return this.put("25519KeysignedKey" + keyId, keyPair);
    }

    removeSignedPreKey(keyId: number) {
        return this.remove("25519KeysignedKey" + keyId);
    }

    loadSession(address: string) {
        return this.get<string>("session" + address);
    }

    storeSession(address: string, record: string) {
        return this.put("session" + address, record);
    }

    removeSession(address: string) {
        return this.remove("session" + address);
    }

    removeAllSessions(jid: string) {
        for (const key in this.store) {
            if (key.startsWith("session" + jid)) {
                delete this.store[key];
            }
        }
    }
}

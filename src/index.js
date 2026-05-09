// Central entry point - re-exports the public API surface

export { util } from "./helpers.js";
export { KeyHelper } from "./KeyHelper.js";
export { Curve } from "./Curve.js";
export { SignalProtocolAddress } from "./SignalProtocolAddress.js";
export { SessionBuilder } from "./SessionBuilder.js";
export { SessionCipher } from "./SessionCipher.js";
export { FingerprintGenerator, NumericFingerprint } from "./NumericFingerprint.js";
export { startWorker, stopWorker } from "./curve25519_worker_manager.js";

// Re-export crypto utilities for public API
export * from "./crypto.js";

// Re-export crypto as a namespace object for backward compat (libomemo.crypto)
import * as cryptoNS from "./crypto.js";
export const crypto = {
    encrypt: cryptoNS.encrypt,
    decrypt: cryptoNS.decrypt,
    calculateMAC: cryptoNS.sign,
    verifyMAC: cryptoNS.verifyMAC,
    getRandomBytes: cryptoNS.getRandomBytes,
};

// Re-export SessionRecord internals that may be needed
export { SessionRecord, BaseKeyType, ChainType } from "./SessionRecord.js";

// Internal namespace for test compatibility
import { SessionRecord, BaseKeyType, ChainType } from "./SessionRecord.js";
import { Curve } from "./Curve.js";
import { queueJobForNumber } from "./SessionLock.js";
import { loadProtocolMessages, loadPushMessages } from "./protobufs.js";
import { internalCrypto } from "./crypto.js";
import {
    encrypt,
    decrypt,
    sign,
    hash,
    HKDFInternal,
    HKDF,
    verifyMAC,
    getRandomBytes,
} from "./crypto.js";

// Internal.crypto is the mutable internalCrypto object, extended with immutable
// helpers. Tests can replace .createKeyPair etc. and all internal callers see it.
Object.assign(internalCrypto, {
    encrypt,
    decrypt,
    sign,
    hash,
    HKDF: HKDFInternal,
    getRandomBytes,
});

export const Internal = {
    crypto: internalCrypto,
    HKDF,
    verifyMAC,
    Curve,
    SessionRecord,
    BaseKeyType,
    ChainType,
    SessionLock: {
        queueJobForNumber,
    },
    protobuf: {
        loadProtocolMessages,
        loadPushMessages,
    },
};

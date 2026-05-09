// Central entry point — public API surface

export { util } from "./helpers.js";
export { KeyHelper } from "./KeyHelper.js";
export { Curve } from "./Curve.js";
export { SignalProtocolAddress } from "./SignalProtocolAddress.js";
export { SessionBuilder } from "./SessionBuilder.js";
export { SessionCipher } from "./SessionCipher.js";
export { FingerprintGenerator, NumericFingerprint } from "./NumericFingerprint.js";
export { startWorker, stopWorker } from "./curve25519_worker_manager.js";

// Low-level crypto utilities
export {
    getRandomBytes,
    encrypt,
    decrypt,
    sign,
    hash,
    HKDF,
    HKDFInternal,
    verifyMAC,
} from "./crypto.js";

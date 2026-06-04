export { util } from "./helpers";
export { KeyHelper } from "./key-helper";
export { Curve25519 } from "./curve";
export { OMEMOAddress } from "./session/address";
export { SessionBuilder } from "./session/builder";
export { SessionCipher } from "./session/cipher";
export { FingerprintGenerator } from "./fingerprint";
export { startWorker, stopWorker } from "./curve25519_worker_manager";

export {
    getRandomBytes,
    encrypt,
    decrypt,
    sign,
    hash,
    HKDF,
    HKDFInternal,
    verifyMAC,
    internalCrypto,
    createKeyPair,
    ECDHE,
    Ed25519Sign,
    Ed25519Verify,
    curvePubKeyToEd25519PubKey,
    ed25519PubKeyToCurvePubKey,
} from "./crypto";

export { BaseKeyType, ChainType } from "./types";
export type { KeyPair, PreKey, SignedPreKey, PublicPreKey } from "./types";

export { SessionRecord } from "./session/record";
export { default as InMemoryStore } from "./session/store";
export { getProtocolProfile } from "./session/protocol-profile";
export type { ProtocolProfile } from "./session/protocol-profile";
export type {
    Direction,
    PreKeyBundle,
    OMEMOStore,
    OMEMOVersion,
    KeyId,
    EncryptResult,
    IdentityKeyError,
} from "./session/types";

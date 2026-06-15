export { util } from "./helpers";
export { KeyHelper } from "./key-helper";
export { OMEMOAddress } from "./session/address";
export { SessionBuilder } from "./session/builder";
export { SessionCipher } from "./session/cipher";
export { FingerprintGenerator } from "./fingerprint";
export { startWorker, stopWorker } from "./curve25519_worker_manager";

// omemo:2 publishes the identity key in Ed25519 form while the library keeps
// Curve25519 internally; consumers need these to derive/display omemo:2
// fingerprints. The remaining crypto primitives are implementation details and
// are intentionally not part of the public API.
export { curvePubKeyToEd25519PubKey, ed25519PubKeyToCurvePubKey } from "./crypto";

export { BaseKeyType, ChainType } from "./types";
export type { KeyPair, PreKey, SignedPreKey, PublicPreKey } from "./types";

export { SessionRecord } from "./session/record";
export { default as InMemoryStore } from "./session/store";
export type {
    Direction,
    PreKeyBundle,
    OMEMOStore,
    OMEMOVersion,
    KeyId,
    EncryptResult,
    DecryptResult,
    IdentityKeyError,
} from "./session/types";

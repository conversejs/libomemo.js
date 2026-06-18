# CHANGES

## 2.0.0 (2026-06-18)

### OMEMO 2 (`urn:xmpp:omemo:2`) support

- Added support for the latest OMEMO version (`urn:xmpp:omemo:2`) alongside the
  existing `eu.siacs.conversations.axolotl` (XEP-0384 v0.3.0). Versions are
  identified by their XML namespace. The two are selected per device via a protocol "profile" that
  encapsulates the differences (HKDF info strings, MAC length and associated data,
  the `OMEMOMessage`/`OMEMOAuthenticatedMessage`/`OMEMOKeyExchange` wire format,
  and Ed25519↔Curve25519 identity-key handling). The Double Ratchet and X3DH
  mechanics are shared across both versions.
- New `curvePubKeyToEd25519PubKey` / `ed25519PubKeyToCurvePubKey` crypto helpers
  (backed by two new WASM exports) for the `omemo:2` Ed25519 identity-key form.
  The Ed25519 identity key is derived from the public key with the Edwards sign
  bit forced to zero, matching `libomemo-c` so the `ik` and authentication
  associated data are byte-compatible with interoperating clients (e.g. Dino).
- New `OMEMOVersion` type identifying the protocol version by its XML namespace.

### Security: enforce the XEP-0384 MAX_SKIP storage limit

- Cap skipped Double-Ratchet message keys at 1000 per receiving chain,
  discarding the oldest first (FIFO). This bounds the storage-flooding DoS
  described in the XEP's "MAX_SKIP" section.

### Breaking: `version` is now a required constructor argument

- `new SessionBuilder(store, address, version)` and
  `new SessionCipher(store, address, version)` now require an explicit OMEMO
  version, given as its XML namespace (`"eu.siacs.conversations.axolotl"` or
  `"urn:xmpp:omemo:2"`). There is no default — wrong-version usage fails at the
  call site rather than silently producing undecryptable messages. A legacy-only
  consumer simply passes `"eu.siacs.conversations.axolotl"`.
- `EncryptResult` gained an optional `kex?: boolean` (omemo:2) and `registrationId`
  is now optional.
- Session storage schema bumped to `v2`: each stored session now records its
  `protocolVersion`. Existing serialized sessions are migrated automatically and
  treated as `eu.siacs.conversations.axolotl`, so persisted sessions remain valid
  across the upgrade.

### Breaking: narrowed public API

- The package entry point now exports only the consumer-facing surface. The
  following low-level helpers are no longer exported (they remain internal
  implementation details): `encrypt`, `decrypt`, `sign`, `hash`, `HKDF`,
  `HKDFInternal`, `verifyMAC`, `ECDHE`, `getRandomBytes`, `createKeyPair`,
  `Ed25519Sign`, `Ed25519Verify`, `internalCrypto`, the `Curve25519` class, and
  `getProtocolProfile` / the `ProtocolProfile` type.
- Still exported: `SessionBuilder`, `SessionCipher`, `KeyHelper`, `OMEMOAddress`,
  `FingerprintGenerator`, `SessionRecord`, `InMemoryStore`, `startWorker` /
  `stopWorker`, `util`, the `curvePubKeyToEd25519PubKey` /
  `ed25519PubKeyToCurvePubKey` conversion helpers, and the public types/enums.

### Breaking: decrypt methods now return a `DecryptResult`

- `SessionCipher.decryptWhisperMessage` and `decryptPreKeyWhisperMessage` now
  resolve to a `DecryptResult` (`{ plaintext, ratchet: { counter, key } }`)
  instead of a bare plaintext `ArrayBuffer`. Existing callers must destructure
  `plaintext` from the result.
- `ratchet.counter` is the message index within the sender's current chain and
  `ratchet.key` is the sender's ratchet (DH) public key in the internal 33-byte
  `0x05`-prefixed curve form. Both are normalized identically across the legacy
  (0.3.0) and `omemo:2` profiles, and let consumers implement protocol rules
  such as the OMEMO heartbeat (XEP-0384).
- New exported `DecryptResult` type.

## 1.0.0

### Breaking: `OMEMOStore` identity methods now receive full address string

- `isTrustedIdentity`, `loadIdentityKey`, and `saveIdentity` now all receive the
  full OMEMOAddress string (`"name.deviceId"`) instead of just the name.
  Previously, `isTrustedIdentity` and `loadIdentityKey` received only the name
  (via `getName()`), while `saveIdentity` received the full address (via
  `toString()`). This was inherited from libsignal-protocol-javascript where it
  made sense (one identity key per account), but is incorrect for OMEMO where
  each device has its own identity key pair.
- The `InMemoryStore` reference implementation now stores identity keys per-device
  (keyed by full address) instead of per-name.
- The `OMEMOStore` interface parameter name changed from `name` to `address` for
  clarity.
- Downstream consumers implementing a custom `OMEMOStore` must update their
  `isTrustedIdentity`, `loadIdentityKey`, and `saveIdentity` implementations to
  expect the full address string.

## 0.0.3

- Added `prepublishOnly` script to ensure full build runs before publishing.
- Restructured scripts: `bundle` handles dts generation and rollup bundling,
  `build` adds native compilation.
- WASM file is now emitted as a rollup asset during bundling instead of being
  manually copied.
- Replaced `new URL('curve25519_compiled.wasm', import.meta.url)` with a plain
  string reference so downstream bundlers (webpack, etc.) don't try to resolve
  the file at bundle time.
- Fixed `__dirname` reference in Emscripten output for ESM compatibility.

## 0.0.2

- Include build and dist files in package

## 0.0.1

> Note: This version still targets XMPP OMEMO version 0.3.0. Support for the
> latest version of OMEMO will be added in a subsequent release.

Here follows a breakdown of changes made to the original
`libsignal-protocol-javascript` which this library is a fork of:

### Breaking: Multiple public functions converted to `async`

Many functions were converted from returning plain Promises to being
`async` functions. This changes how validation errors are surfaced:

- **Validation errors no longer throw synchronously.** Previously, passing
  invalid arguments would throw a `TypeError` immediately. These errors are
  now returned as rejected promises.

- **Synchronous `try/catch` no longer works.** Code like this will silently
  miss the error and produce an unhandled rejection:

    ```js
    // TypeError is never caught here
    try {
        KeyHelper.generatePreKey("bad");
    } catch (e) {
        // never reached
    }
    ```

- **Callers must handle the returned promise.** Always use `.then()/.catch()` or `await`:

    ```js
    // Correct usage
    try {
        await KeyHelper.generatePreKey(keyId);
    } catch (e) {
        // handles validation errors and crypto failures
    }
    ```

#### Affected functions

**`KeyHelper`:**

- `KeyHelper.generateSignedPreKey(identityKeyPair, keyId)`
- `KeyHelper.generatePreKey(keyId)`

**`Curve.async`:**

- `Curve.async.generateKeyPair()`
- `Curve.async.createKeyPair(privKey)`
- `Curve.async.calculateAgreement(pubKey, privKey)`
- `Curve.async.verifySignature(pubKey, msg, sig)`
- `Curve.async.calculateSignature(privKey, message)`

**`FingerprintGenerator`:**

- `FingerprintGenerator.prototype.createFor(localIdentifier, localIdentityKey, remoteIdentifier, remoteIdentityKey)`

**`SessionCipher`:**

- `SessionCipher.prototype.decryptWhisperMessage(buffer, encoding)`
- `SessionCipher.prototype.getRemoteRegistrationId()`
- `SessionCipher.prototype.hasOpenSession()`
- `SessionCipher.prototype.closeOpenSessionForDevice()`
- `SessionCipher.prototype.deleteAllSessionsForDevice()`

**`crypto.js` exports:**

- `encrypt(key, data, iv)`
- `decrypt(key, data, iv)`
- `sign(key, data)`
- `HKDFInternal(input, salt, info)`
- `verifyMAC(data, key, mac, length)`
- `internalCrypto.createKeyPair(privKey)`
- `internalCrypto.ECDHE(pubKey, privKey)`
- `internalCrypto.Ed25519Sign(privKey, message)`
- `internalCrypto.Ed25519Verify(pubKey, msg, sig)`
- `createKeyPair(privKey)`
- `ECDHE(pubKey, privKey)`
- `Ed25519Sign(privKey, message)`
- `Ed25519Verify(pubKey, msg, sig)`

### Full TypeScript Rewrite

All source files have been migrated from JavaScript to TypeScript with strict
type checking. The library now ships bundled `.d.ts` type declarations.

### Module System

- **ES modules** with named exports are now the primary distribution format.
- **UMD bundle** available as `libomemo.umd.js` with a `libomemo` global
  (replaces the old `libsignal` global).
- The `Internal` namespace has been removed. All functionality is exported
  directly.

### Package Renamed

- Package name is now `libomemo.js` (was `libsignal-protocol-javascript`).
- Repository moved to `github:conversejs/libomemo.js`.

### Removed Dependencies

- **`dcodeIO.ByteBuffer`** — removed. Use `util.toString()` and
  `util.toArrayBuffer()` or native `TextEncoder`/`Uint8Array`.
- **`Long`** — removed.
- **`dcodeIO.ProtoBuf`** — replaced with `protobufjs` v8. Proto files are
  loaded from string variables at build time (no network fetch needed).

### `OMEMOAddress` (formerly `SignalProtocolAddress`)

- Renamed from `SignalProtocolAddress` to `OMEMOAddress`.
- Added static `OMEMOAddress.fromString(encodedAddress)` for parsing
  `"name.deviceId"` format.
- Added `equals(other)` method for comparison.
- **Security fix**: ReDoS vulnerability in `fromString` fixed by replacing
  the regex with a safe validation pattern (`/^[^.]+\.\d+$/`).

### `SessionRecord`

- Completely rewritten with improved serialization/deserialization logic.
- Added `SessionRecord.isSessionOpen(sessionState)` static method.
- `getSessionByBaseKey()` now accepts `ArrayBuffer | string | Uint8Array`.
- Added `deleteAllSessions()` method.
- Exported as a value (not just a type) so consumers can call static methods.

### `InMemoryStore`

- Reference implementation of `OMEMOStore` is now exported directly from the
  library. Useful for testing and as a template for persistent stores.

### New Type Exports

The following types are now exported for consumers implementing custom stores
or handling encryption results:

- `Direction` — `SENDING = 1`, `RECEIVING = 2`
- `PreKeyBundle` — bundle format for `SessionBuilder.processPreKey()`
- `OMEMOStore` — interface for custom store implementations
- `KeyId` — `number | string`
- `EncryptResult` — return type of `SessionCipher.encrypt()`
- `IdentityKeyError` — error with `.identityKey` property
- `KeyPair`, `PreKey`, `SignedPreKey`, `PublicPreKey`

### Web Worker Security

- Added `ALLOWED_METHODS` whitelist to the curve25519 worker to prevent
  arbitrary method calls via worker messages.

### Source Maps

- Source maps are now enabled for all build outputs (ESM, UMD, and worker).

### Build System

- **Grunt replaced with Rollup** for bundling.
- `npm run compile` compiles native C code with Emscripten.
- `npm run dist` builds TypeScript to ESM + UMD bundles.
- `npm run build:dts` generates `.d.ts` type declarations.

### Curve25519 / OMEMO Spec Compliance

- `xed25519_sign` replaces `curve25519_sign` for OMEMO spec compliance.
- `xed25519_verify` replaces `curve25519_verify` to match.
- `curve25519_sign` and `curve25519_verify` are no longer exported from the
  WASM module.

### `FingerprintGenerator`

- New class for generating safety number fingerprints for identity
  verification. Constructor takes an `iterations` count. Call
  `createFor(localIdentifier, localIdentityKey, remoteIdentifier,
remoteIdentityKey)` to get a fingerprint string.

### Job Queue / Locking

- All session operations for a given address are now serialized through
  `queueJobForNumber` to prevent race conditions.

### Full TypeScript Rewrite

All source files have been migrated from JavaScript to TypeScript with strict
type checking. The library now ships bundled `.d.ts` type declarations.

### Module System

- **ES modules** with named exports are now the primary distribution format.
- **UMD bundle** available as `libomemo.umd.js` with a `libomemo` global
  (replaces the old `libsignal` global).
- The `Internal` namespace has been removed. All functionality is exported
  directly.

### Package Renamed

- Package name is now `libomemo.js` (was `libsignal-protocol-javascript`).
- Repository moved to `github:conversejs/libomemo.js`.

### Removed Dependencies

- **`dcodeIO.ByteBuffer`** — removed. Use `util.toString()` and
  `util.toArrayBuffer()` or native `TextEncoder`/`Uint8Array`.
- **`Long`** — removed.
- **`dcodeIO.ProtoBuf`** — replaced with `protobufjs` v8. Proto files are
  loaded from string variables at build time (no network fetch needed).

### `OMEMOAddress` (formerly `SignalProtocolAddress`)

- Renamed from `SignalProtocolAddress` to `OMEMOAddress`.
- Added static `OMEMOAddress.fromString(encodedAddress)` for parsing
  `"name.deviceId"` format.
- Added `equals(other)` method for comparison.
- **Security fix**: ReDoS vulnerability in `fromString` fixed by replacing
  the regex with a safe validation pattern (`/^[^.]+\.\d+$/`).

### `SessionRecord`

- Completely rewritten with improved serialization/deserialization logic.
- Added `SessionRecord.isSessionOpen(sessionState)` static method.
- `getSessionByBaseKey()` now accepts `ArrayBuffer | string | Uint8Array`.
- Added `deleteAllSessions()` method.
- Exported as a value (not just a type) so consumers can call static methods.

### `InMemoryStore`

- Reference implementation of `OMEMOStore` is now exported directly from the
  library. Useful for testing and as a template for persistent stores.

### New Type Exports

The following types are now exported for consumers implementing custom stores
or handling encryption results:

- `Direction` — `SENDING = 1`, `RECEIVING = 2`
- `PreKeyBundle` — bundle format for `SessionBuilder.processPreKey()`
- `OMEMOStore` — interface for custom store implementations
- `KeyId` — `number | string`
- `EncryptResult` — return type of `SessionCipher.encrypt()`
- `IdentityKeyError` — error with `.identityKey` property
- `KeyPair`, `PreKey`, `SignedPreKey`, `PublicPreKey`

### Web Worker Security

- Added `ALLOWED_METHODS` whitelist to the curve25519 worker to prevent
  arbitrary method calls via worker messages.

### Source Maps

- Source maps are now enabled for all build outputs (ESM, UMD, and worker).

### Build System

- **Grunt replaced with Rollup** for bundling.
- `npm run compile` compiles native C code with Emscripten.
- `npm run dist` builds TypeScript to ESM + UMD bundles.
- `npm run build:dts` generates `.d.ts` type declarations.

### Curve25519 / OMEMO Spec Compliance

- `xed25519_sign` replaces `curve25519_sign` for OMEMO spec compliance.
- `xed25519_verify` replaces `curve25519_verify` to match.
- `curve25519_sign` and `curve25519_verify` are no longer exported from the
  WASM module.

### `FingerprintGenerator`

- New class for generating safety number fingerprints for identity
  verification. Constructor takes an `iterations` count. Call
  `createFor(localIdentifier, localIdentityKey, remoteIdentifier, remoteIdentityKey)` to get a fingerprint string.

### Job Queue / Locking

- All session operations for a given address are now serialized through
  `queueJobForNumber` to prevent race conditions.

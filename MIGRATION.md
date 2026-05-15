# Migration Guide: libsignal-protocol.js → libomemo.js

This guide covers all breaking changes and API differences when migrating from
`libsignal-protocol.js` to `libomemo.js`, the OMEMO-compliant fork used by
Converse.js.

## 1. Module System & Imports

**Before (libsignal):** The library exposed a global `libsignal` object (UMD)
with nested namespaces like `libsignal.KeyHelper`, `libsignal.SessionBuilder`,
etc. All source files used `Internal` as a shared namespace object.

**After (libomemo):** Pure ES modules with named exports. No global namespaces.
Import directly:

```typescript
import {
    KeyHelper,
    SessionBuilder,
    SessionCipher,
    SessionRecord,
    OMEMOAddress,
    Curve25519,
    FingerprintGenerator,
    InMemoryStore,
    startWorker,
    stopWorker,
    BaseKeyType,
    ChainType,
    util,
} from "libomemo.js";
```

The library also ships a UMD bundle with a `libomemo` global (instead of
`libsignal`).

## 2. Address Class Renamed

`signalProtocol.Address` → `OMEMOAddress`

```typescript
// Before
const address = new libsignal.SignalProtocolAddress(name, deviceId);

// After
import { OMEMOAddress } from "libomemo.js";
const address = new OMEMOAddress(name, deviceId);
```

- `getName()` and `getDeviceId()` methods remain.
- `toString()` returns `"name.deviceId"` format.
- New static `OMEMOAddress.fromString(encodedAddress)` parses the string format
  back.
- `equals(other)` method for comparison.
- The `fromString` regex was replaced with a safe pattern (`/^[^.]+\.\d+$/`) to
  fix a ReDoS vulnerability.

## 3. Store Interface (`OMEMOStore`)

The store interface is mostly the same but with these changes:

- **Method signatures are typed** — `loadPreKey`, `storePreKey`,
  `removePreKey`, `loadSignedPreKey`, `storeSignedPreKey`,
  `removeSignedPreKey` now accept `KeyId` (`number | string`) instead of just
  `number`.
- **`isTrustedIdentity`** returns `Promise<boolean> | boolean` (can be sync or
  async).
- **`saveIdentity`** returns `Promise<boolean> | boolean`.
- All session methods (`loadSession`, `storeSession`, etc.) are typed.

The reference `InMemoryStore` implementation is exported directly from the
library — use it as a template for your own persistent store or for testing.

## 4. KeyHelper Changes

- **`generateIdentityKeyPair()`** — now returns `Promise<KeyPair>` (was already
  async).
- **`generateSignedPreKey(identityKeyPair, signedKeyId)`** — async, returns
  `Promise<SignedPreKey>`.
- **`generatePreKey(keyId)`** — async, returns `Promise<PreKey>`.
- **`generateRegistrationId()`** — synchronous, returns `number` (unchanged).

All `KeyHelper` methods are now `async`. Make sure to `await` them.

## 5. SessionBuilder Changes

- **`processPreKey(bundle)`** — returns `Promise<void>`. Internally uses a job
  queue to prevent race conditions per address.
- **`processV3(record, message)`** — internal method, the `message` parameter
  is now typed as `PreKeyWhisperMessageProto` (was untyped `any`).

The constructor accepts either an `OMEMOAddress` or a string in
`"name.deviceId"` format.

## 6. SessionCipher Changes

- **`encrypt(buffer)`** — now accepts `ArrayBuffer | string | Uint8Array` (was
  just `ArrayBuffer`). Returns `Promise<EncryptResult>`.
- **`decryptWhisperMessage(buffer, encoding)`** — accepts
  `string | ArrayBuffer | Uint8Array`.
- **`decryptPreKeyWhisperMessage(buffer, encoding)`** — same input flexibility.
- **`getRemoteRegistrationId()`** — returns
  `Promise<number | undefined | null>`.
- **`hasOpenSession()`** — returns `Promise<boolean>`.
- **`closeOpenSessionForDevice()`** — returns `Promise<void>`.
- **`deleteAllSessionsForDevice()`** — returns `Promise<void>`.

Constructor accepts `OMEMOStore` and `OMEMOAddress | string`.

## 7. SessionRecord Changes

- **`SessionRecord.deserialize(serialized)`** — static method, returns
  `SessionRecord`.
- **`SessionRecord.isSessionOpen(sessionState)`** — static method to check if a
  session is open.
- **`serialize()`** — returns JSON string.
- **`hasOpenSession()`**, **`getOpenSession()`**, **`getSessions()`**,
  **`getSessionByBaseKey(baseKey)`** — instance methods.
- **`updateSessionState(session)`**, **`archiveCurrentState()`**,
  **`promoteState(session)`** — lifecycle methods.
- **`deleteAllSessions()`** — clears all stored sessions.

The `baseKey` parameter of `getSessionByBaseKey` now accepts
`ArrayBuffer | string | Uint8Array`.

## 8. Removed Dependencies

- **`dcodeIO.ByteBuffer`** — removed. String-to-ArrayBuffer conversion now
  uses native `TextEncoder`/`Uint8Array`. The `util.toString` and
  `util.toArrayBuffer` helpers are still available.
- **`dcodeIO.ProtoBuf`** — replaced with `protobufjs` v8. Proto files are loaded
  from string variables at build time (no network fetch needed).
- **`Long`** — removed.
- **`jquery`** — removed from tests.

## 9. Cryptographic Changes

### Curve25519

- **`xed25519_sign`** replaces `curve25519_sign` for OMEMO spec compliance. The
  `KeyHelper.generateSignedPreKey` now uses `Ed25519Sign` internally.
- **`xed25519_verify`** replaces `curve25519_verify` to match.
- `curve25519_sign` and `curve25519_verify` are no longer exported from the
  WASM module.

### Crypto API

The `internalCrypto` object and individual exports (`createKeyPair`, `ECDHE`,
`Ed25519Sign`, `Ed25519Verify`, `encrypt`, `decrypt`, `sign`, `hash`, `HKDF`,
`verifyMAC`, `getRandomBytes`) are all async and return `Promise`s.

## 10. New Features

- **`FingerprintGenerator`** — generates safety number fingerprints for identity
  verification. Constructor takes `iterations` count. Call
  `createFor(localIdentifier, localIdentityKey, remoteIdentifier,
remoteIdentityKey)` to get a fingerprint string.
- **Web Worker support** — `startWorker(url)` and `stopWorker()` for offloading
  curve25519 operations. The worker has an `ALLOWED_METHODS` whitelist for
  security.
- **Job queue / locking** — all session operations for a given address are
  serialized through `queueJobForNumber` to prevent race conditions.
- **Source maps** — enabled for all build outputs.

## 11. Type Exports

All types are exported from the library. Key types to be aware of:

| Type               | Description                                                    |
| ------------------ | -------------------------------------------------------------- |
| `KeyPair`          | `{ pubKey: ArrayBuffer, privKey: ArrayBuffer }`                |
| `PreKey`           | `{ keyId: number, keyPair: KeyPair }`                          |
| `SignedPreKey`     | `{ keyId: number, keyPair: KeyPair, signature: ArrayBuffer }`  |
| `PublicPreKey`     | `{ publicKey?: ArrayBuffer, keyId: number }`                   |
| `PreKeyBundle`     | The bundle passed to `SessionBuilder.processPreKey()`          |
| `EncryptResult`    | `{ type: number, body: string, registrationId: number }`       |
| `OMEMOStore`       | The interface your store implementation must satisfy           |
| `Direction`        | `SENDING = 1`, `RECEIVING = 2` — used by `isTrustedIdentity`   |
| `KeyId`            | `number` or `string` — accepted by prekey store methods        |
| `IdentityKeyError` | Error with `.identityKey: ArrayBuffer` property                |
| `SessionRecord`    | Class for managing persisted session state (exported as value) |

## 12. Build System

| Command           | Description                                             |
| ----------------- | ------------------------------------------------------- |
| `npm run compile` | Compiles native C code with Emscripten (must run first) |
| `npm run dist`    | Builds TypeScript to ESM + UMD bundles                  |
| `npm run build`   | compile + dist                                          |
| `npm run dev`     | Watch mode                                              |
| `npm test`        | Runs tests in ChromeHeadless                            |

## 13. Security Fixes

- **ReDoS vulnerability** in `OMEMOAddress.fromString` — the regex was replaced
  with a safe validation pattern (`/^[^.]+\.\d+$/`).
- **Worker method whitelist** — the curve25519 worker only allows a fixed set of
  methods, preventing arbitrary code execution via worker messages.

## Migration Checklist for Converse.js

1. Replace `libsignal` import with `libomemo.js` named exports.
2. Replace `SignalProtocolAddress` with `OMEMOAddress`.
3. Update store implementation to match `OMEMOStore` interface (note `KeyId`
   can be `number | string`).
4. Ensure all `KeyHelper` calls are `await`ed.
5. Replace `dcodeIO.ByteBuffer` usage with native `TextEncoder`/`Uint8Array` or
   use `libomemo.util`.
6. Update any direct usage of `curve25519_sign`/`curve25519_verify` to use
   `Ed25519Sign`/`Ed25519Verify`.
7. If using the UMD build, change `libsignal` global to `libomemo`.
8. Consider using `FingerprintGenerator` for safety number display.
9. Optionally enable the Web Worker for better performance:
   `startWorker("/path/to/curve25519_worker.js")`.

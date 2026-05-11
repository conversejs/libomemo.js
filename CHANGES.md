# CHANGES

## 3.0.0

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

# CHANGES

## 3.0.0

### Breaking: `KeyHelper.generateSignedPreKey` and `KeyHelper.generatePreKey` are now `async`

Both functions were converted from returning a plain Promise to being `async`
functions. This changes how validation errors are surfaced:

- **Validation errors no longer throw synchronously.** Previously, passing an
  invalid `identityKeyPair` or `keyId` would throw a `TypeError` immediately.
  These errors are now returned as rejected promises.

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

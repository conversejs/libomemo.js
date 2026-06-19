# libomemo.js

[![CI Tests](https://github.com/conversejs/libomemo.js/actions/workflows/karma-tests.yml/badge.svg)](https://github.com/conversejs/libomemo.js/actions/workflows/karma-tests.yml)
[![npm version](https://img.shields.io/npm/v/libomemo.js.svg)](https://www.npmjs.com/package/libomemo.js)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](http://www.gnu.org/licenses/gpl-3.0.html)

> **Note:** this library has not yet undergone a formal third-party security
> audit. Review the code before relying on it, and please report any suspected
> vulnerability privately as described in [`SECURITY.md`](./SECURITY.md).

**libomemo.js** is a TypeScript implementation of the [OMEMO Multi-End Message and Object Encryption](https://xmpp.org/extensions/xep-0384.html) protocol for [XMPP](https://xmpp.org).
It provides ratcheting forward secrecy for synchronous and asynchronous messaging environments, enabling secure multi-device encrypted communication.

This library supports both version 0.3.0, which is what most XMPP clients support today,
and the latest version 0.9.1 (also known as OMEMO2 or NEWMEMO).

The two versions are identified by their XML namespaces:

- the legacy version is **`eu.siacs.conversations.axolotl`**
- and the current one is **`urn:xmpp:omemo:2`**.

The version is chosen per device when constructing a `SessionBuilder`/`SessionCipher` — see [Selecting the OMEMO version](#selecting-the-omemo-version).

This library is crypto-only: it implements the X3DH key agreement and Double Ratchet, and produces/consumes the per-device ratchet wire format.
Building XMPP stanzas, PEP bundles/device lists, and the XEP-0420 SCE payload encryption are the responsibility of the consumer (e.g. [Converse](https://github.com/conversejs/converse.js)).

This library started as a fork of [libsignal-protocol-javascript](https://github.com/signalapp/libsignal-protocol-javascript) by Open Whisper Systems
and has been modernized, ported to TypeScript and adapted for the XMPP OMEMO specification. NodeJS support has also been added.

The OMEMO 2 (`urn:xmpp:omemo:2`) support reuses Curve25519&harr;Ed25519 field operations from
[libomemo-c](https://github.com/dino/libomemo-c) (the C library used by [Dino](https://dino.im));
see [Acknowledgements](#acknowledgements).

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
    - [Setup](#setup)
    - [Building a Session](#building-a-session)
    - [Encrypting Messages](#encrypting-messages)
    - [Decrypting Messages](#decrypting-messages)
    - [Selecting the OMEMO version](#selecting-the-omemo-version)
- [API Reference](#api-reference)
    - [KeyHelper](#keyhelper)
    - [SessionBuilder](#sessionbuilder)
    - [SessionCipher](#sessioncipher)
    - [OMEMOAddress](#omemoaddress)
    - [Crypto Utilities](#crypto-utilities)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [LLM and GenAI usage](#llm-and-genai-usage)
- [License](#license)

## Features

- **Double Ratchet Protocol** — Forward secrecy and post-compromise security
- **Multi-device support** — Encrypt messages for multiple devices simultaneously
- **PreKey management** — Asynchronous session establishment via PreKey bundles
- **TypeScript native** — Full type definitions included
- **Browser & Node.js compatible** — ESM, UMD, and CommonJS support
- **Curve25519** — High-performance elliptic curve cryptography (compiled via Emscripten)

## Installation

```bash
npm install libomemo.js
```

Or include the UMD build directly in your webpage:

```html
<script src="dist/libomemo.umd.js"></script>
```

## Requirements

This library requires a modern JavaScript environment with support for:

- [`ArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer)
- [`TypedArray`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray)
- [`Promise`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
- [`WebCrypto`](https://developer.mozilla.org/en-US/docs/Web/API/Crypto) with:
    - AES-CBC
    - HMAC SHA-256

These are available in all modern browsers and Node.js 15+.

## Quick Start

### Import

```js
// ES Modules
import { KeyHelper, SessionBuilder, SessionCipher, OMEMOAddress } from "libomemo.js";

// CommonJS
const { KeyHelper, SessionBuilder, SessionCipher, OMEMOAddress } = require("libomemo.js");

// Browser (UMD)
const { KeyHelper, SessionBuilder, SessionCipher, OMEMOAddress } = libomemo;
```

### Setup

Generate identity keys, registration ID, and PreKeys at install time:

```js
const registrationId = KeyHelper.generateRegistrationId();
// Store registrationId somewhere durable and safe.

const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
// Store identityKeyPair somewhere durable and safe.

const preKey = await KeyHelper.generatePreKey(keyId);
store.storePreKey(preKey.keyId, preKey.keyPair);

const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, keyId, version);
store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);

// Register preKeys and signedPreKey with the XMPP server
```

### Building a Session

Implement a storage interface for managing keys and session state (see `src/session/store.ts` for an example), then establish sessions:

```js
const store = new MyOMEMOProtocolStore();
const address = new OMEMOAddress(recipientId, deviceId);
// The OMEMO version is required (no default); it is the protocol's XML namespace:
// "eu.siacs.conversations.axolotl" (XEP-0384 v0.3.0) or "urn:xmpp:omemo:2".
const sessionBuilder = new SessionBuilder(store, address, "urn:xmpp:omemo:2");

// Process a PreKey bundle from the server
try {
    await sessionBuilder.processPreKey({
        registrationId: <Number>,
        identityKey: <ArrayBuffer>,
        signedPreKey: {
            keyId: <Number>,
            publicKey: <ArrayBuffer>,
            signature: <ArrayBuffer>
        },
        preKey: {
            keyId: <Number>,
            publicKey: <ArrayBuffer>
        }
    });
    // Session established — ready to encrypt
} catch (error) {
    // Handle identity key conflict
}
```

### Encrypting Messages

```js
const sessionCipher = new SessionCipher(store, address, "urn:xmpp:omemo:2");
const ciphertext = await sessionCipher.encrypt("Hello world");
// ciphertext -> { type: <Number>, body: <string>, kex?: <boolean> }
// For omemo:2, `kex` indicates whether `body` is an OMEMOKeyExchange (true)
// or a plain OMEMOAuthenticatedMessage (false).
```

### Decrypting Messages

Both decrypt methods resolve to a `DecryptResult`:

```js
const sessionCipher = new SessionCipher(store, address, "urn:xmpp:omemo:2");

// Decrypt a PreKey/key-exchange message (establishes session if needed)
try {
    const { plaintext } = await sessionCipher.decryptPreKeyWhisperMessage(ciphertext);
} catch (error) {
    // Handle identity key conflict
}

// Decrypt a regular message using existing session
const { plaintext, ratchet } = await sessionCipher.decryptWhisperMessage(ciphertext);
// `ratchet.counter` (message index in the sender's chain) and `ratchet.key`
// (the sender's 33-byte 0x05-prefixed ratchet public key) let you implement
// protocol rules such as the OMEMO heartbeat.
```

### Selecting the OMEMO version

OMEMO `eu.siacs.conversations.axolotl` and `urn:xmpp:omemo:2` are distinct wire protocols with separate sessions,
bundles, and PEP nodes. Which one to use is decided **per recipient device**,
based on the version(s) that device advertises (i.e. which device-list PEP node
it publishes to). Pass that version to every `SessionBuilder`/`SessionCipher`
for that device. There is intentionally no default — passing the wrong version
fails loudly rather than silently producing an undecryptable message.

For `omemo:2`, the identity key is published in its **Ed25519** form. Derive it
from your Curve25519 identity key when building your bundle:

```js
import { curvePubKeyToEd25519PubKey } from "libomemo.js";

const ik = await curvePubKeyToEd25519PubKey(identityKeyPair.pubKey); // 32-byte Ed25519
```

This matches the encoding used by `libomemo-c` (and thus interoperating clients
such as Dino): the Ed25519 identity key is derived from the public key with the
Edwards sign bit forced to zero.

A peer's `omemo:2` bundle/key-exchange carries that same Ed25519 identity key;
pass it through unchanged as `identityKey` and the library converts it to
Curve25519 internally for the key agreement.

## API Reference

### KeyHelper

Key generation utilities for OMEMO protocol setup.

| Method                                                  | Description                                                 |
| ------------------------------------------------------- | ----------------------------------------------------------- |
| `generateRegistrationId()`                              | Generate a unique registration ID                           |
| `generateIdentityKeyPair()`                             | Generate an identity key pair                               |
| `generatePreKey(keyId)`                                 | Generate an unsigned PreKey                                 |
| `generateSignedPreKey(identityKeyPair, keyId, version)` | Generate a signed PreKey (`version` is the OMEMO namespace) |

### SessionBuilder

Handles session establishment with remote recipients.

| Method                        | Description                          |
| ----------------------------- | ------------------------------------ |
| `processPreKey(preKeyBundle)` | Build a session from a PreKey bundle |

### SessionCipher

Encrypts and decrypts messages for established sessions.

| Method                                    | Description                    |
| ----------------------------------------- | ------------------------------ |
| `encrypt(plaintext)`                      | Encrypt a message              |
| `decryptPreKeyWhisperMessage(ciphertext)` | Decrypt and establish session  |
| `decryptWhisperMessage(ciphertext)`       | Decrypt using existing session |

### OMEMOAddress

Represents a recipient address (JID + device ID tuple).

```js
const address = new OMEMOAddress(recipientId, deviceId);
```

### Crypto Utilities

Low-level cryptographic functions for advanced use cases:

`getRandomBytes`, `encrypt`, `decrypt`, `sign`, `hash`, `HKDF`, `verifyMAC`, `createKeyPair`, `ECDHE`, `Ed25519Sign`, `Ed25519Verify`

## Building from Source

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Emscripten](https://emscripten.org/docs/getting_started/downloads.html) (for compiling native Curve25519 code)

### Build Commands

```bash
# Install dependencies
npm install

# Compile native Curve25519 code (requires Emscripten)
npm run compile

# Build TypeScript distribution
npm run dist

# Full build (compile + dist)
npm run build

# Watch mode for development
npm run dev
```

## Testing

```bash
# Run all tests (Node.js + Headless Chrome)
npm test

# Run tests in Chrome browser
npm run test:browser

# Run tests in headless Chrome only
npm run test:headless

# Run Node.js tests only
npm run test:node
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`npm test`) and linting (`npm run lint`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

Please ensure all new functionality includes tests and follows existing code conventions.

## Acknowledgements

Thank you to the [NLNet Foundation](https://nlnet.nl/) for sponsoring work on this library.

- [libsignal-protocol-javascript](https://github.com/signalapp/libsignal-protocol-javascript)
  by Open Whisper Systems — the original codebase this library was forked from.
- [libomemo-c](https://github.com/dino/libomemo-c) — the OMEMO 2 support reuses its
  Curve25519&harr;Ed25519 field operations (`fe_montx_to_edy` / `fe_edy_to_montx` and the
  supporting `fe_*`/`ge_*` files under `native/ed25519/additions/`), and the conversion
  wrappers in `native/ed25519/additions/omemo_convert.c` follow its approach so the on-wire
  identity-key encoding interoperates with libomemo-c-based clients such as Dino.

## LLM and GenAI usage

Large Language Models (DeepSeek 4 Pro, Qwen 3.7 max and Claude Opus 4.8) were used
to assist with tasks such as writing code, editing text and research.

**Where AI was not used:** no cryptographic primitive or protocol logic was
designed or invented by an LLM. The cryptographic core derives from established,
widely-reviewed sources:

- [libsignal](https://github.com/signalapp/libsignal-protocol-javascript) for the Double Ratchet and X3DH
- [libomemo-c](https://github.com/dino/libomemo-c) for the OMEMO 2 Curve25519 & Ed25519 operations

AI assistance was limited to porting, tests, tooling and documentation.

Correctness is checked independently of any AI:

- the test suite runs on Node.js and in a real browser (via Playwright) against
  known-answer test vectors;
- the omemo:2 wire format is pinned by a cross-implementation interop vector
  generated by libomemo-c (the C library [Dino](https://dino.im) uses): the
  suite decrypts libomemo-c's real ciphertexts and verifies its signatures, and
  the reverse direction (libomemo-c decrypting this library's output) is
  confirmed out of band.

Any LLM-generated content is carefully and manually reviewed, as would any 3rd
party contribution. A human maintainer remains responsible for every line
regardless of how it was drafted.

## License

- Copyright 2015-2018 Open Whisper Systems
- Copyright 2022-2026 JC Brand
- Licensed under the GPLv3: [http://www.gnu.org/licenses/gpl-3.0.html](http://www.gnu.org/licenses/gpl-3.0.html)

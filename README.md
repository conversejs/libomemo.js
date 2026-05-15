# libomemo.js

[![CI Tests](https://github.com/conversejs/libomemo.js/actions/workflows/karma-tests.yml/badge.svg)](https://github.com/conversejs/libomemo.js/actions/workflows/karma-tests.yml)
[![npm version](https://img.shields.io/npm/v/libomemo.js.svg)](https://www.npmjs.com/package/libomemo.js)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](http://www.gnu.org/licenses/gpl-3.0.html)
**libomemo.js** is a TypeScript implementation of the [OMEMO Multi-End Message and Object Encryption](https://xmpp.org/extensions/attic/xep-0384-0.3.0.html) protocol for [XMPP](https://xmpp.org). It provides ratcheting forward secrecy for synchronous and asynchronous messaging environments, enabling secure multi-device encrypted communication.

A fork of [libsignal-protocol-javascript](https://github.com/signalapp/libsignal-protocol-javascript) by Open Whisper Systems, adapted for the XMPP OMEMO specification.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
    - [Setup](#setup)
    - [Building a Session](#building-a-session)
    - [Encrypting Messages](#encrypting-messages)
    - [Decrypting Messages](#decrypting-messages)
- [API Reference](#api-reference)
    - [KeyHelper](#keyhelper)
    - [SessionBuilder](#sessionbuilder)
    - [SessionCipher](#sessioncipher)
    - [OMEMOAddress](#omemoaddress)
    - [Crypto Utilities](#crypto-utilities)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Contributing](#contributing)
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

const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, keyId);
store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);

// Register preKeys and signedPreKey with the XMPP server
```

### Building a Session

Implement a storage interface for managing keys and session state (see `src/session/store.ts` for an example), then establish sessions:

```js
const store = new MyOMEMOProtocolStore();
const address = new OMEMOAddress(recipientId, deviceId);
const sessionBuilder = new SessionBuilder(store, address);

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
const sessionCipher = new SessionCipher(store, address);
const ciphertext = await sessionCipher.encrypt("Hello world");
// ciphertext -> { type: <Number>, body: <string> }
```

### Decrypting Messages

```js
const sessionCipher = new SessionCipher(store, address);

// Decrypt a PreKey message (establishes session if needed)
try {
    const plaintext = await sessionCipher.decryptPreKeyWhisperMessage(ciphertext);
} catch (error) {
    // Handle identity key conflict
}

// Decrypt a regular message using existing session
const plaintext = await sessionCipher.decryptWhisperMessage(ciphertext);
```

## API Reference

### KeyHelper

Key generation utilities for OMEMO protocol setup.

| Method                                         | Description                       |
| ---------------------------------------------- | --------------------------------- |
| `generateRegistrationId()`                     | Generate a unique registration ID |
| `generateIdentityKeyPair()`                    | Generate an identity key pair     |
| `generatePreKey(keyId)`                        | Generate an unsigned PreKey       |
| `generateSignedPreKey(identityKeyPair, keyId)` | Generate a signed PreKey          |

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

## License

Copyright 2015-2018 Open Whisper Systems
Copyright 2022-2026 JC Brand

Licensed under the GPLv3: [http://www.gnu.org/licenses/gpl-3.0.html](http://www.gnu.org/licenses/gpl-3.0.html)

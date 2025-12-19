# Agent Guide for libomemo.js

This guide provides essential information for agents working with the libomemo.js codebase,
a JavaScript implementation of the Signal Protocol for OMEMO encryption in XMPP.

## Project Overview

This is a fork of [libsignal-protocol-javascript](https://github.com/signalapp/libsignal-protocol-javascript) modified to conform to the XMPP [OMEMO](https://xmpp.org/extensions/attic/xep-0384-0.3.0.html) specification.

## Code Organization

```
/dist       # Distributables
/build      # Intermediate build files
/src        # JS source files
/native     # C source files for curve25519
/protos     # Protobuf definitions
/test       # Tests
```

## Key Components

- **Curve.js**: Wrapper for Curve25519 cryptographic operations
- **KeyHelper.js**: Functions for generating keys and registration IDs
- **SessionBuilder.js**: Establishes sessions using PreKey bundles
- **SessionCipher.js**: Encrypts/decrypts messages for established sessions
- **SessionRecord.js**: Manages session state persistence
- **SignalProtocolAddress.js**: Represents addressing for Signal Protocol
- **crypto.js**: Cryptographic utilities
- **helpers.js**: General helper functions
- **protobufs.js**: Protobuf serialization/deserialization
- **NumericFingerprint.js**: Device fingerprinting functionality

## Essential Commands

### Development Setup
```bash
# Install dependencies
npm install

# Or using Makefile
make node_modules
```

### Building
```bash
# Compile native C code (requires Emscripten)
make compile

# Build JavaScript distribution
make dist

# Full build (compile + dist)
make build

# Watch mode for development
grunt dev
```

### Testing
```bash
# Run tests with Karma
make test

# Run tests with custom arguments
make test ARGS="--single-run"

# Lint source files
make eslint
```

### Code Quality
```bash
# Run ESLint on source and test files
./node_modules/.bin/eslint src/**/*.js test/**/*.js Gruntfile.js
```

## Code Patterns and Conventions

### Asynchronous Operations
- Most cryptographic operations return Promises
- Uses native Promise syntax (no polyfills needed)
- Async/await is supported but not heavily used

### Error Handling
- Throwing Errors for invalid inputs/validation failures
- Promise rejection for cryptographic operation failures
- Console warnings for non-fatal issues

### Data Types
- Primary use of ArrayBuffer for binary data
- Uint8Array for byte manipulation
- Promises for asynchronous operations

### Module System
- Uses IIFE (Immediately Invoked Function Expression) pattern
- Internal functions in `Internal` namespace
- Public API exposed through `libsignal` global object

### Naming Conventions
- CamelCase for functions and variables
- PascalCase for constructor functions/classes
- Constants in UPPER_CASE
- Descriptive function names that indicate purpose

## Testing Approach

### Framework
- Uses Mocha test framework
- Chai assertion library
- Karma test runner for browser testing

### Test Structure
- Test files located in `/test` directory
- Each component typically has a corresponding test file
- Uses in-memory store implementation for testing (`InMemorySignalProtocolStore.js`)

### Running Tests
Tests are run in Chrome browser by default and cover:
- Key generation and management
- Session establishment
- Message encryption/decryption
- Protocol compliance

## Important Gotchas

1. **Native Dependencies**: Curve25519 operations depend on compiled C code via Emscripten. Must run `make compile` before building.
2. **Browser Environment**: Requires modern browser features (ArrayBuffer, TypedArray, Promise, WebCrypto).
3. **Asynchronous Nature**: Many operations return promises. Ensure proper handling of async flows.
4. **Identity Management**: Identity key conflicts must be handled explicitly during session building.
5. **Session State**: Session state must be persisted properly between uses. Implementation is left to the developer (see `SignalProtocolStore`).
6. **PreKey Management**: Proper PreKey handling is critical for secure communication setup.

## File Formats

### Protocol Buffers
- Uses ProtoBuf.js for serialization
- Definitions in `/protos` directory
- Compiled versions used in build process

## Build Process

1. Native C code compilation using Emscripten
2. Concatenation of JavaScript files in specific order
3. Wrapping with IIFE for proper scoping
4. Generation of distributable file in `/dist`

## Configuration Files

- **package.json**: Project dependencies and metadata
- **Gruntfile.js**: Build configuration and tasks
- **karma.conf.js**: Test runner configuration
- **.eslintrc.js**: ESLint configuration
- **Makefile**: High-level build and test commands

## Contributing Notes

- Changes should maintain backward compatibility when possible
- All new functionality should include tests
- Follow existing code style and patterns
- Ensure builds pass all tests before submitting changes

# Agent Guide for libomemo.js

This guide provides essential information for agents working with the libomemo.js codebase,
a TypeScript implementation of the Double Ratchet Protocol for OMEMO encryption in XMPP.

## Project Overview

This is a fork of [libsignal-protocol-javascript](https://github.com/signalapp/libsignal-protocol-javascript)
modified to conform to the XMPP [OMEMO](https://xmpp.org/extensions/attic/xep-0384-0.3.0.html) specification.

## Code Organization

```
/dist       # Distributables (ESM, UMD, and type definitions)
/build      # Intermediate build files (compiled native code, generated types)
/src        # TypeScript source files
/native     # C source files for curve25519
/protos     # Protobuf definitions
/test       # TypeScript test files
```

## Key Components

- **curve.ts**: Wrapper for Curve25519 cryptographic operations
- **key-helper.ts**: Functions for generating keys and registration IDs
- **session/builder.ts**: Establishes sessions using PreKey bundles
- **session/cipher.ts**: Encrypts/decrypts messages for established sessions
- **session/record.ts**: Manages session state persistence
- **session/address.ts**: Represents addressing for Signal Protocol (OMEMOAddress)
- **crypto.ts**: Cryptographic utilities
- **helpers.ts**: General helper functions
- **protobufs.ts**: Protobuf serialization/deserialization
- **fingerprint.ts**: Device fingerprinting functionality
- **curve25519_worker.ts**: Web Worker for curve25519 operations
- **curve25519_worker_manager.ts**: Worker lifecycle management

## Essential Commands

### Development Setup

```bash
# Install dependencies
npm install
```

### Building

```bash
# Compile native C code (requires Emscripten)
npm run compile

# Build TypeScript distribution (includes type generation and Rollup bundling)
npm run dist

# Full build (compile native + dist)
npm run build

# Watch mode for development
npm run dev
```

### Testing

```bash
# Run tests with Karma (builds first, then runs in ChromeHeadless)
npm test

# Run tests in Chrome browser
npm run test:browser
```

### Code Quality

```bash
# Run ESLint on source and test files
npm run lint

# Fix linting issues automatically
npm run lint:fix

# Format code with Prettier
npm run format

# Type check without emitting files
npm run typecheck
```

## Code Patterns and Conventions

### Error Handling

- Throwing Errors for invalid inputs/validation failures
- Promise rejection for cryptographic operation failures
- Console warnings for non-fatal issues

### Data Types

- Primary use of ArrayBuffer for binary data
- Uint8Array for byte manipulation
- Promises for asynchronous operations
- TypeScript types and interfaces for type safety

### Module System

- ES Modules with named exports
- Rollup bundles to ESM and UMD formats
- Public API exposed through named exports and `libomemo` global (UMD)

### Naming Conventions

- camelCase for functions and variables
- PascalCase for classes and interfaces
- UPPER_CASE for constants
- Descriptive function names that indicate purpose
- TypeScript interfaces and types for public APIs

## Testing Approach

### Framework

- Uses Mocha test framework
- Chai assertion library
- Karma test runner for browser testing

### Test Structure

- Test files located in `/test` directory (TypeScript)
- Each component typically has a corresponding test file
- Uses in-memory store implementations for testing

### Running Tests

Tests are run in ChromeHeadless browser by default and cover:

- Key generation and management
- Session establishment
- Message encryption/decryption
- Protocol compliance

## Important Gotchas

1. **Native Dependencies**: Curve25519 operations depend on compiled C code via Emscripten. Must run `npm run compile` before building.
2. **Browser Environment**: Requires modern browser features (ArrayBuffer, TypedArray, Promise, WebCrypto).
3. **Asynchronous Nature**: Many operations return promises. Ensure proper handling of async flows.
4. **Identity Management**: Identity key conflicts must be handled explicitly during session building.
5. **Session State**: Session state must be persisted properly between uses. Implementation is left to the developer.
6. **PreKey Management**: Proper PreKey handling is critical for secure communication setup.
7. **TypeScript**: All source and test files are TypeScript. Use proper type annotations.
8. **Rollup**: Build system uses Rollup for bundling. Configuration is in `rollup.config.js`.

## File Formats

### Protocol Buffers

- Uses protobufjs for serialization
- Definitions in `/protos` directory
- Loaded via rollup-plugin-string in build process

## Build Process

1. Native C code compilation using Emscripten
2. TypeScript type declaration generation
3. Rollup bundling to ESM and UMD formats
4. WASM file copied to dist directory
5. Type definitions bundled to single index.d.ts

## Configuration Files

- **package.json**: Project dependencies and metadata
- **rollup.config.js**: Build configuration and bundling
- **tsconfig.json**: TypeScript compiler configuration
- **tsconfig.dts.json**: Type declaration generation configuration
- **karma.conf.js**: Test runner configuration
- **.prettierrc.json**: Prettier formatting configuration
- **Makefile**: High-level build and test commands

## Contributing Notes

- Changes should maintain backward compatibility when possible
- All new functionality should include tests
- Follow existing TypeScript patterns and conventions
- Ensure builds pass all tests before submitting changes

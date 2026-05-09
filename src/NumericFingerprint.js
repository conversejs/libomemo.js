import { hash } from "./crypto.js";

const VERSION = 0;

function iterateHash(data, key, count) {
    const combinedData = new Uint8Array(data.byteLength + key.byteLength);
    combinedData.set(new Uint8Array(data), 0);
    combinedData.set(new Uint8Array(key), data.byteLength);
    return hash(combinedData.buffer).then((result) => {
        if (--count === 0) {
            return result;
        }
        return iterateHash(result, key, count);
    });
}

function getEncodedChunk(hashBytes, offset) {
    const chunk =
        (hashBytes[offset] * Math.pow(2, 32) +
            hashBytes[offset + 1] * Math.pow(2, 24) +
            hashBytes[offset + 2] * Math.pow(2, 16) +
            hashBytes[offset + 3] * Math.pow(2, 8) +
            hashBytes[offset + 4]) %
        100000;
    let s = chunk.toString();
    while (s.length < 5) {
        s = "0" + s;
    }
    return s;
}

function getDisplayStringFor(identifier, key, iterations) {
    const versionUint16Array = new Uint16Array([VERSION]);
    const versionLength = versionUint16Array.buffer.byteLength;

    const keyUint8Array = new Uint8Array(key);
    const keyLength = keyUint8Array.buffer.byteLength;

    const identifierUint8Array = new TextEncoder().encode(identifier);
    const identifierLength = identifierUint8Array.buffer.byteLength;

    const combinedBuffer = new Uint8Array(versionLength + keyLength + identifierLength);
    combinedBuffer.set(versionUint16Array, 0);
    combinedBuffer.set(keyUint8Array, versionLength);
    combinedBuffer.set(identifierUint8Array, versionLength + keyLength);
    return iterateHash(combinedBuffer.buffer, key, iterations).then((output) => {
        output = new Uint8Array(output);
        return (
            getEncodedChunk(output, 0) +
            getEncodedChunk(output, 5) +
            getEncodedChunk(output, 10) +
            getEncodedChunk(output, 15) +
            getEncodedChunk(output, 20) +
            getEncodedChunk(output, 25)
        );
    });
}

export class FingerprintGenerator {
    #iterations;

    constructor(iterations) {
        this.#iterations = iterations;
    }

    createFor(localIdentifier, localIdentityKey, remoteIdentifier, remoteIdentityKey) {
        if (
            typeof localIdentifier !== "string" ||
            typeof remoteIdentifier !== "string" ||
            !(localIdentityKey instanceof ArrayBuffer) ||
            !(remoteIdentityKey instanceof ArrayBuffer)
        ) {
            throw new Error("Invalid arguments");
        }

        return Promise.all([
            getDisplayStringFor(localIdentifier, localIdentityKey, this.#iterations),
            getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this.#iterations),
        ]).then((fingerprints) => fingerprints.sort().join(""));
    }
}

// Legacy alias
export { FingerprintGenerator as NumericFingerprint };

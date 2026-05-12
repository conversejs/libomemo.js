import { hash } from "./crypto";

const VERSION = 0;

export class FingerprintGenerator {
    #iterations: number;

    constructor(iterations: number) {
        this.#iterations = iterations;
    }

    #getEncodedChunk(hashBytes: Uint8Array, offset: number): string {
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

    async #iterateHash(data: ArrayBuffer, key: ArrayBuffer, count: number): Promise<ArrayBuffer> {
        const combinedData = new Uint8Array(data.byteLength + key.byteLength);
        combinedData.set(new Uint8Array(data), 0);
        combinedData.set(new Uint8Array(key), data.byteLength);
        const result = await hash(combinedData.buffer);
        if (--count === 0) {
            return result;
        }
        return this.#iterateHash(result, key, count);
    }

    async #getDisplayStringFor(
        identifier: string,
        key: ArrayBuffer,
        iterations: number
    ): Promise<string> {
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

        const output = new Uint8Array(
            await this.#iterateHash(combinedBuffer.buffer, key, iterations)
        );
        return (
            this.#getEncodedChunk(output, 0) +
            this.#getEncodedChunk(output, 5) +
            this.#getEncodedChunk(output, 10) +
            this.#getEncodedChunk(output, 15) +
            this.#getEncodedChunk(output, 20) +
            this.#getEncodedChunk(output, 25)
        );
    }

    async createFor(
        localIdentifier: string,
        localIdentityKey: ArrayBuffer,
        remoteIdentifier: string,
        remoteIdentityKey: ArrayBuffer
    ): Promise<string> {
        if (
            typeof localIdentifier !== "string" ||
            typeof remoteIdentifier !== "string" ||
            !(localIdentityKey instanceof ArrayBuffer) ||
            !(remoteIdentityKey instanceof ArrayBuffer)
        ) {
            throw new Error("Invalid arguments");
        }

        const fingerprints = await Promise.all([
            this.#getDisplayStringFor(localIdentifier, localIdentityKey, this.#iterations),
            this.#getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this.#iterations),
        ]);

        return fingerprints.sort().join("");
    }
}

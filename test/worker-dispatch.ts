import { expect } from "chai";
import { afterEach, vi } from "vitest";
import { internalCrypto } from "../src/crypto.js";
import { startWorker, stopWorker } from "../src/curve25519_worker_manager.js";
import { assertEqualArrayBuffers } from "./utils.js";

const WORKER_URL = "/dist/libomemo-worker.js";
const MISSING_WORKER_URL = "/dist/this-worker-does-not-exist.js";

/**
 * Exercises the startWorker() dispatch path: with a worker started, internalCrypto
 * must route every operation through it (proven by the absence of a fallback log),
 * and a worker that fails to load must fall back to the local backend and log once.
 * Browser-only: needs the Worker API and the built /dist/libomemo-worker.js.
 */
describe("Worker-backed curve dispatch", function () {
    if (typeof process !== "undefined" && process.versions && process.versions.node) {
        it.skip("Worker dispatch tests require a browser environment", function () {});
        return;
    }

    afterEach(function () {
        stopWorker();
    });

    it("routes all six curve operations through the worker", async function () {
        // A genuine worker run never logs; a fallback always does. Zero calls here
        // proves the operations really ran in the worker, not on the main thread.
        const errorSpy = vi.spyOn(console, "error");
        startWorker(WORKER_URL);

        const a = await internalCrypto.createKeyPair();
        const b = await internalCrypto.createKeyPair();
        expect(a.pubKey.byteLength).to.equal(33);
        expect(a.privKey.byteLength).to.equal(32);

        // ECDHE is symmetric in the two keypairs.
        const ab = await internalCrypto.ECDHE(a.pubKey, b.privKey);
        const ba = await internalCrypto.ECDHE(b.pubKey, a.privKey);
        assertEqualArrayBuffers(ab, ba);

        // Sign then verify round-trips.
        const msg = new TextEncoder().encode("omemo worker dispatch").buffer;
        const sig = await internalCrypto.Ed25519Sign(a.privKey, msg);
        expect(sig.byteLength).to.equal(64);
        await internalCrypto.Ed25519Verify(a.pubKey, msg, sig);

        // OMEMO 2 IdentityKey conversions are offloaded too.
        const ed = await internalCrypto.curvePubKeyToEd25519PubKey(a.pubKey);
        expect(ed.byteLength).to.equal(32);
        const curveAgain = await internalCrypto.ed25519PubKeyToCurvePubKey(ed);
        expect(curveAgain.byteLength).to.equal(32);

        expect(errorSpy.mock.calls.length).to.equal(0);
        errorSpy.mockRestore();
    });

    it("propagates an operation error (tampered signature) without falling back", async function () {
        const errorSpy = vi.spyOn(console, "error");
        startWorker(WORKER_URL);

        const key = await internalCrypto.createKeyPair();
        const msg = new TextEncoder().encode("hello").buffer;
        const sig = await internalCrypto.Ed25519Sign(key.privKey, msg);
        const tampered = sig.slice(0);
        new Uint8Array(tampered)[0] ^= 0xff;

        let threw = false;
        try {
            await internalCrypto.Ed25519Verify(key.pubKey, msg, tampered);
        } catch {
            threw = true;
        }
        expect(threw).to.equal(true);
        // A rejected signature is a legitimate result from a healthy worker, so it
        // must not be mistaken for a transport failure and trigger a fallback log.
        expect(errorSpy.mock.calls.length).to.equal(0);
        errorSpy.mockRestore();
    });

    it("falls back to the local backend and logs when the worker fails to load", async function () {
        const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
        startWorker(MISSING_WORKER_URL);

        // Succeeds via the local wasm despite the unusable worker.
        const key = await internalCrypto.createKeyPair();
        expect(key.pubKey.byteLength).to.equal(33);
        expect(errorSpy.mock.calls.length).to.be.greaterThan(0);
        errorSpy.mockRestore();
    });
});

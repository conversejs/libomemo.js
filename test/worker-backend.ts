import { expect } from "chai";
import { beforeEach, afterEach, vi } from "vitest";
import { internalCrypto } from "../src/crypto.js";
import { startWorker, stopWorker } from "../src/curve25519_worker_manager.js";

/**
 * Node-runnable unit tests for the worker dispatch state machine
 * (curve25519_worker_manager.ts). Instead of a real Web Worker, they install a
 * fake `globalThis.Worker` so every branch (healthy dispatch, method-name
 * mapping, operation-error vs transport-error, timeout, crash, and teardown) can
 * be driven deterministically. The fallback path exercises the real local wasm
 * backend, so these run under `test:node` (i.e. in CI), where the real
 * Worker-backed integration tests in worker-dispatch.ts are skipped.
 */

const WORKER_URL = "/dist/libomemo-worker.js";

interface WorkerRequest {
    id: number;
    methodName: string;
    args: unknown[];
}

interface Reply {
    ok?: boolean;
    result?: unknown;
    error?: string;
}

/** A well-formed success reply, i.e. one carrying the explicit `ok: true`. */
function ok(result?: unknown): Reply {
    return { ok: true, result };
}

/** A responder decides how the fake worker answers a request. Returning
 * `undefined` leaves the request unanswered, simulating a hung worker. */
type Responder = (methodName: string, args: unknown[]) => Reply | undefined;

class FakeWorker {
    static created: FakeWorker[] = [];
    static constructShouldThrow = false;

    readonly url: string;
    readonly posted: WorkerRequest[] = [];
    terminated = false;
    responder: Responder | undefined;

    onmessage: ((e: MessageEvent) => void) | null = null;
    onerror: ((e: ErrorEvent) => void) | null = null;
    onmessageerror: ((e: MessageEvent) => void) | null = null;

    constructor(url: string) {
        if (FakeWorker.constructShouldThrow) {
            throw new Error("failed to construct worker (bad URL / CSP)");
        }
        this.url = url;
        FakeWorker.created.push(this);
    }

    postMessage(msg: WorkerRequest): void {
        this.posted.push(msg);
        const reply = this.responder?.(msg.methodName, msg.args);
        if (!reply) return; // hang: never answer this request
        // Deliver asynchronously, the way a real worker would.
        queueMicrotask(() => {
            this.onmessage?.({ data: { id: msg.id, ...reply } } as unknown as MessageEvent);
        });
    }

    terminate(): void {
        this.terminated = true;
    }

    /** Fire a transport-level failure (script/load error or in-worker crash). */
    emitError(message: string): void {
        this.onerror?.({ message } as unknown as ErrorEvent);
    }

    /** The single worker startWorker() created for the current test. */
    static only(): FakeWorker {
        expect(FakeWorker.created.length).to.equal(1);
        return FakeWorker.created[0];
    }
}

function buf(len: number, fill = 0): ArrayBuffer {
    return new Uint8Array(len).fill(fill).buffer;
}

/** A well-formed keypair reply, so createKeyPair dispatch resolves cleanly. */
function keyPairReply(): Reply {
    return ok({ pubKey: buf(33, 5), privKey: buf(32, 1) });
}

describe("WorkerCurveBackend dispatch (Node, fake worker)", function () {
    let savedWorker: typeof Worker;
    let errorSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(function () {
        savedWorker = globalThis.Worker;
        globalThis.Worker = FakeWorker as unknown as typeof Worker;
        FakeWorker.created = [];
        FakeWorker.constructShouldThrow = false;
        // Suppress and observe the single fallback log line.
        errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    });

    afterEach(function () {
        stopWorker();
        errorSpy.mockRestore();
        globalThis.Worker = savedWorker;
    });

    it("dispatches to the worker and returns its reply verbatim (no fallback)", async function () {
        startWorker(WORKER_URL);
        const worker = FakeWorker.only();
        // A sentinel pubKey the local wasm could never produce; if we get it back,
        // the operation genuinely ran in the worker rather than falling back.
        const sentinelPub = buf(33, 0xab);
        worker.responder = () => ok({ pubKey: sentinelPub, privKey: buf(32, 0xcd) });

        const key = await internalCrypto.createKeyPair();

        expect(new Uint8Array(key.pubKey)).to.deep.equal(new Uint8Array(sentinelPub));
        expect(worker.posted).to.have.length(1);
        expect(worker.posted[0].methodName).to.equal("createKeyPair");
        expect(errorSpy.mock.calls.length).to.equal(0);
    });

    it("maps each CurveBackend operation to its worker protocol method name", async function () {
        startWorker(WORKER_URL);
        const worker = FakeWorker.only();
        worker.responder = () => ok(buf(32));

        await internalCrypto.createKeyPair(buf(32));
        await internalCrypto.ECDHE(buf(33, 5), buf(32));
        await internalCrypto.Ed25519Sign(buf(32), buf(4));
        // verifySignature succeeds by resolving with no value, so only `ok: true`
        // distinguishes this from a malformed reply.
        worker.responder = () => ok(undefined);
        await internalCrypto.Ed25519Verify(buf(33, 5), buf(4), buf(64));
        worker.responder = () => ok(buf(32));
        await internalCrypto.curvePubKeyToEd25519PubKey(buf(33, 5));
        await internalCrypto.ed25519PubKeyToCurvePubKey(buf(32));

        expect(worker.posted.map((m) => m.methodName)).to.deep.equal([
            "createKeyPair",
            "calculateAgreement",
            "calculateSignature",
            "verifySignature",
            "curvePubKeyToEd25519PubKey",
            "ed25519PubKeyToCurvePubKey",
        ]);
        expect(errorSpy.mock.calls.length).to.equal(0);
    });

    it("propagates an operation error from the worker without falling back", async function () {
        startWorker(WORKER_URL);
        FakeWorker.only().responder = () => ({ ok: false, error: "Invalid signature" });

        let caught: Error | undefined;
        try {
            await internalCrypto.Ed25519Verify(buf(33, 5), buf(4), buf(64));
        } catch (e) {
            caught = e as Error;
        }

        expect(caught).to.be.instanceOf(Error);
        expect(caught?.message).to.equal("Invalid signature");
        // A rejected signature is a legitimate worker result, not a transport
        // failure, so it must neither log nor latch to the local backend.
        expect(errorSpy.mock.calls.length).to.equal(0);
        expect(FakeWorker.only().terminated).to.equal(false);
    });

    it("falls back to the local backend (and logs once) when the worker cannot be constructed", async function () {
        FakeWorker.constructShouldThrow = true;
        startWorker(WORKER_URL);

        // No worker was constructed; the call must still succeed via local wasm.
        const key = await internalCrypto.createKeyPair();
        expect(key.pubKey.byteLength).to.equal(33);
        expect(FakeWorker.created).to.have.length(0);
        expect(errorSpy.mock.calls.length).to.equal(1);
    });

    it("falls back, logs once, and terminates the worker when it crashes mid-call", async function () {
        startWorker(WORKER_URL);
        const worker = FakeWorker.only(); // responder unset: the call will hang

        const pending = internalCrypto.createKeyPair();
        worker.emitError("worker boom"); // transport failure while the op is in flight
        const key = await pending;

        expect(key.pubKey.byteLength).to.equal(33); // completed on the local backend
        expect(errorSpy.mock.calls.length).to.equal(1);
        // Leak fix: the crashed worker must be terminated, not just dereferenced.
        expect(worker.terminated).to.equal(true);
    });

    it("times out a hung worker, falls back, and terminates it (leak fix)", async function () {
        startWorker(WORKER_URL, { timeout: 25 });
        const worker = FakeWorker.only(); // responder unset: the worker never replies

        const key = await internalCrypto.createKeyPair();

        expect(key.pubKey.byteLength).to.equal(33); // rescued by the timeout + fallback
        expect(errorSpy.mock.calls.length).to.equal(1);
        // A hung worker is still a live thread; the timeout path must terminate it.
        expect(worker.terminated).to.equal(true);
    });

    it("after a transport failure, later ops go straight to local with no extra logs", async function () {
        startWorker(WORKER_URL, { timeout: 25 });
        const worker = FakeWorker.only();

        await internalCrypto.createKeyPair(); // trips the timeout, latches to local
        expect(errorSpy.mock.calls.length).to.equal(1);

        // Subsequent calls must not re-post to the dead worker nor log again.
        const postedBefore = worker.posted.length;
        const key = await internalCrypto.createKeyPair();
        expect(key.pubKey.byteLength).to.equal(33);
        expect(worker.posted.length).to.equal(postedBefore);
        expect(errorSpy.mock.calls.length).to.equal(1);
    });

    it("fails closed on a reply that does not assert success", async function () {
        // The pre-fix protocol inferred success from the absence of an error, so a
        // reply carrying neither (a stale worker build, a truncated or foreign
        // message) resolved the job. For verifySignature, which reports success by
        // resolving with no value, that is an accepted signature. Every shape below
        // must therefore be treated as a transport failure, never as a result.
        const malformed: Reply[] = [
            { result: undefined }, // no `ok`: indistinguishable from a valid verify
            { result: "whatever" },
            { ok: false, error: "" }, // an Error built with no message
            { ok: false }, // a thrown non-Error, whose `.message` was undefined
        ];

        for (const reply of malformed) {
            stopWorker();
            FakeWorker.created = [];
            errorSpy.mockClear();
            startWorker(WORKER_URL);
            const worker = FakeWorker.only();
            worker.responder = () => reply;

            let caught: Error | undefined;
            try {
                // Falls back to the real local wasm, which rejects these junk inputs.
                await internalCrypto.Ed25519Verify(buf(33, 5), buf(4), buf(64));
            } catch (e) {
                caught = e as Error;
            }

            expect(caught, `reply ${JSON.stringify(reply)} must not verify`).to.be.instanceOf(
                Error
            );
            // An unintelligible worker is dropped, not trusted for later replies.
            expect(worker.terminated).to.equal(true);
            expect(errorSpy.mock.calls.length).to.equal(1);
        }
    });

    it("stopWorker terminates a healthy worker and reverts to the local backend", async function () {
        startWorker(WORKER_URL);
        const worker = FakeWorker.only();
        worker.responder = () => keyPairReply();
        await internalCrypto.createKeyPair(); // ran in the worker

        stopWorker();
        expect(worker.terminated).to.equal(true);

        // With no worker, ops now run on local wasm and produce a real key.
        FakeWorker.created = [];
        const key = await internalCrypto.createKeyPair();
        expect(key.pubKey.byteLength).to.equal(33);
        expect(FakeWorker.created).to.have.length(0);
    });

    it("rejects an in-flight op when stopWorker races it, completing on local", async function () {
        startWorker(WORKER_URL);
        const worker = FakeWorker.only(); // responder unset: op stays in flight

        const pending = internalCrypto.createKeyPair();
        stopWorker(); // rejects the in-flight job as a transport failure
        const key = await pending;

        expect(key.pubKey.byteLength).to.equal(33); // finished on the local backend
        expect(worker.terminated).to.equal(true);
    });

    it("timeout: 0 disables the per-op timeout (arms no timer)", async function () {
        // `??` (not `||`) in startWorker must keep an explicit 0; a `||` regression
        // would substitute the 10s default and this would arm a timer.
        const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");
        try {
            startWorker(WORKER_URL, { timeout: 0 });
            const worker = FakeWorker.only();
            worker.responder = () => keyPairReply();

            setTimeoutSpy.mockClear(); // ignore anything before the operation
            const key = await internalCrypto.createKeyPair();

            expect(key.pubKey.byteLength).to.equal(33); // dispatched to and answered by the worker
            expect(worker.posted).to.have.length(1);
            // The disabled timeout means post() must not schedule a fallback timer.
            expect(setTimeoutSpy.mock.calls.length).to.equal(0);
            expect(errorSpy.mock.calls.length).to.equal(0);
        } finally {
            setTimeoutSpy.mockRestore();
        }
    });

    it("a second startWorker replaces and terminates the first worker", async function () {
        startWorker(WORKER_URL);
        const first = FakeWorker.only();
        first.responder = () => keyPairReply();
        await internalCrypto.createKeyPair(); // ran in the first worker
        expect(first.posted).to.have.length(1);

        startWorker(WORKER_URL); // stops the first, installs a second
        expect(first.terminated).to.equal(true);
        expect(FakeWorker.created).to.have.length(2);

        const second = FakeWorker.created[1];
        second.responder = () => keyPairReply();
        const firstPostedBefore = first.posted.length;

        await internalCrypto.createKeyPair(); // must now run in the second worker
        expect(second.posted).to.have.length(1);
        expect(first.posted.length).to.equal(firstPostedBefore); // nothing new to the old worker
    });
});

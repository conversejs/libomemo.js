import { CurveBackend, KeyPair } from "./types";
import { getLocalCurveBackend, resetCurveBackend, setCurveBackend } from "./crypto";

/**
 * How long to wait for a worker reply before treating the worker as hung. A hung
 * worker (deadlocked, or killed by the browser without firing `onerror`) would
 * otherwise leave the operation pending forever. Curve operations take single-digit
 * milliseconds, so this is generous; the first call also covers worker startup and
 * wasm compilation. Configurable per `startWorker`; pass `0` (or a non-finite value)
 * to disable.
 */
const DEFAULT_WORKER_TIMEOUT_MS = 10_000;

interface Job {
    resolve: (result: unknown) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout> | undefined;
}

interface WorkerResponse {
    id: number;
    result?: unknown;
    error?: string;
}

/**
 * A failure of the worker itself: the script failed to load, the worker crashed,
 * or the URL/CSP made it unconstructable. This is distinct from an operation the
 * worker ran and legitimately rejected (e.g. an invalid signature), which comes
 * back as a normal error reply. Only a transport failure triggers a fallback to
 * the local backend.
 */
class WorkerTransportError extends Error {}

/**
 * Low-level message transport to the curve25519 Web Worker. Each `post()` is one
 * request/reply keyed by id. A normal error reply rejects just that job (an
 * operation error). A worker-level failure rejects every pending job with a
 * WorkerTransportError and notifies the owner through `onTransportError`.
 */
class Curve25519Worker {
    #jobs = new Map<number, Job>();
    #jobId = 0;
    #dead = false;
    readonly #timeoutMs: number;
    readonly worker: Worker;
    onTransportError: (error: WorkerTransportError) => void = () => {};

    constructor(url: string, timeoutMs: number) {
        this.#timeoutMs = timeoutMs;
        this.worker = new Worker(url); // may throw synchronously (bad URL / CSP)
        this.worker.onmessage = (e: MessageEvent<WorkerResponse>) => this.#onMessage(e.data);
        this.worker.onerror = (e: ErrorEvent) =>
            this.#fail(new WorkerTransportError(e.message || "curve25519 worker error"));
        this.worker.onmessageerror = () =>
            this.#fail(new WorkerTransportError("curve25519 worker message error"));
    }

    #onMessage(data: WorkerResponse): void {
        const job = this.#take(data.id);
        if (!job) return;
        if (data.error !== undefined) {
            job.reject(new Error(data.error)); // operation error: caller must not fall back
        } else {
            job.resolve(data.result);
        }
    }

    // Remove a job from the pending set and cancel its timeout, returning it.
    #take(id: number): Job | undefined {
        const job = this.#jobs.get(id);
        if (!job) return undefined;
        this.#jobs.delete(id);
        if (job.timer !== undefined) clearTimeout(job.timer);
        return job;
    }

    // A job whose reply did not arrive in time: the worker is hung, so treat it as
    // a transport failure (which fails every pending job and latches to fallback).
    #onTimeout(id: number): void {
        if (!this.#jobs.has(id)) return;
        this.#fail(new WorkerTransportError("curve25519 worker timed out"));
    }

    #fail(error: WorkerTransportError): void {
        if (this.#dead) return;

        this.#dead = true;
        for (const job of this.#jobs.values()) {
            if (job.timer !== undefined) clearTimeout(job.timer);
            job.reject(error);
        }
        this.#jobs.clear();
        this.onTransportError(error);
    }

    post(methodName: string, args: unknown[]): Promise<unknown> {
        if (this.#dead) {
            return Promise.reject(new WorkerTransportError("curve25519 worker is not available"));
        }

        return new Promise((resolve, reject) => {
            const id = this.#jobId++;
            const timer =
                this.#timeoutMs > 0 && isFinite(this.#timeoutMs)
                    ? setTimeout(() => this.#onTimeout(id), this.#timeoutMs)
                    : undefined;
            this.#jobs.set(id, { resolve, reject, timer });
            this.worker.postMessage({ id, methodName, args });
        });
    }

    terminate(): void {
        // Reject any in-flight jobs as a transport failure so the backend can
        // finish them on the fallback rather than leaving them pending forever.
        for (const job of this.#jobs.values()) {
            if (job.timer !== undefined) clearTimeout(job.timer);
            job.reject(new WorkerTransportError("curve25519 worker was stopped"));
        }
        this.#jobs.clear();
        this.#dead = true;
        this.worker.terminate();
    }
}

/**
 * A CurveBackend that runs operations in the Web Worker and falls back to a local
 * backend when the worker fails at the transport level. Operation errors reported
 * by the worker (a rejected signature, an all-zero shared secret) propagate
 * unchanged. Method-name mapping: ECDHE -> calculateAgreement,
 * Ed25519Sign -> calculateSignature, Ed25519Verify -> verifySignature; the rest
 * share their names with the worker protocol.
 */
class WorkerCurveBackend implements CurveBackend {
    #transport: Curve25519Worker | null = null;
    readonly #fallback: CurveBackend;
    #loggedFailure = false;

    constructor(url: string, fallback: CurveBackend, timeoutMs: number) {
        this.#fallback = fallback;
        try {
            const transport = new Curve25519Worker(url, timeoutMs);
            transport.onTransportError = (err) => this.#onTransportError(err);
            this.#transport = transport;
        } catch (err) {
            this.#onTransportError(
                err instanceof WorkerTransportError ? err : new WorkerTransportError(String(err))
            );
        }
    }

    #onTransportError(error: Error): void {
        if (!this.#loggedFailure) {
            this.#loggedFailure = true;
            console.error(
                "libomemo.js: the curve25519 worker failed; falling back to the local backend.",
                error
            );
        }

        // Terminate the failed worker before dropping the reference. A timed-out
        // worker is still a live thread, and `onerror` fires for any uncaught error
        // without killing the worker, so neither case is self-cleaning.
        const transport = this.#transport;
        this.#transport = null;
        transport?.terminate();
    }

    async #run<T>(methodName: string, args: unknown[], local: () => Promise<T>): Promise<T> {
        const transport = this.#transport;
        if (!transport) return local();

        try {
            return (await transport.post(methodName, args)) as T;
        } catch (error) {
            // The worker died mid-call; #onTransportError has already latched us
            // to the fallback, so just complete this operation there.
            if (error instanceof WorkerTransportError) return local();
            throw error; // operation error: propagate
        }
    }

    createKeyPair(privKey: ArrayBuffer): Promise<KeyPair> {
        return this.#run("createKeyPair", [privKey], () => this.#fallback.createKeyPair(privKey));
    }

    ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#run("calculateAgreement", [pubKey, privKey], () =>
            this.#fallback.ECDHE(pubKey, privKey)
        );
    }

    Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#run("calculateSignature", [privKey, message], () =>
            this.#fallback.Ed25519Sign(privKey, message)
        );
    }

    Ed25519Verify(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void> {
        return this.#run("verifySignature", [pubKey, msg, sig], () =>
            this.#fallback.Ed25519Verify(pubKey, msg, sig)
        );
    }

    curvePubKeyToEd25519PubKey(pubKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#run("curvePubKeyToEd25519PubKey", [pubKey], () =>
            this.#fallback.curvePubKeyToEd25519PubKey(pubKey)
        );
    }

    ed25519PubKeyToCurvePubKey(edPubKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#run("ed25519PubKeyToCurvePubKey", [edPubKey], () =>
            this.#fallback.ed25519PubKeyToCurvePubKey(edPubKey)
        );
    }

    terminate(): void {
        this.#transport?.terminate();
        this.#transport = null;
    }
}

let activeWorkerBackend: WorkerCurveBackend | null = null;

/**
 * Offload curve operations to the Web Worker at `url` (typically the bundled
 * `dist/libomemo-worker.js`). Subsequent OMEMO crypto runs off the main thread.
 * If the worker cannot be loaded, or a call does not get a reply within
 * `options.timeout` ms, calls fall back to the local backend: the bundled wasm in
 * the default build, or a thrown error in the `worker-client` build, which has no
 * local wasm.
 *
 * @param url      URL of the worker script (must be same-origin / CSP-permitted).
 * @param options.timeout  Per-operation reply timeout in milliseconds
 *                 (default 10000). Pass 0 to disable the timeout.
 */
export function startWorker(url: string, options: { timeout?: number } = {}): void {
    stopWorker();
    const timeoutMs = options.timeout ?? DEFAULT_WORKER_TIMEOUT_MS;
    const backend = new WorkerCurveBackend(url, getLocalCurveBackend(), timeoutMs);
    activeWorkerBackend = backend;
    setCurveBackend(backend);
}

/** Stop offloading and revert curve operations to the local backend. */
export function stopWorker(): void {
    if (activeWorkerBackend) {
        activeWorkerBackend.terminate();
        activeWorkerBackend = null;
    }
    resetCurveBackend();
}

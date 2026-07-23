import { CurveBackend, KeyPair } from "./types";
import { getLocalCurveBackend, resetCurveBackend, setCurveBackend } from "./crypto";

interface Job {
    resolve: (result: unknown) => void;
    reject: (error: Error) => void;
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
    readonly worker: Worker;
    onTransportError: (error: WorkerTransportError) => void = () => {};

    constructor(url: string) {
        this.worker = new Worker(url); // may throw synchronously (bad URL / CSP)
        this.worker.onmessage = (e: MessageEvent<WorkerResponse>) => this.#onMessage(e.data);
        this.worker.onerror = (e: ErrorEvent) =>
            this.#fail(new WorkerTransportError(e.message || "curve25519 worker error"));
        this.worker.onmessageerror = () =>
            this.#fail(new WorkerTransportError("curve25519 worker message error"));
    }

    #onMessage(data: WorkerResponse): void {
        const job = this.#jobs.get(data.id);
        if (!job) return;

        this.#jobs.delete(data.id);

        if (data.error !== undefined) {
            job.reject(new Error(data.error)); // operation error: caller must not fall back
        } else {
            job.resolve(data.result);
        }
    }

    #fail(error: WorkerTransportError): void {
        if (this.#dead) return;

        this.#dead = true;
        for (const job of this.#jobs.values()) job.reject(error);

        this.#jobs.clear();
        this.onTransportError(error);
    }

    post(methodName: string, args: unknown[]): Promise<unknown> {
        if (this.#dead) {
            return Promise.reject(new WorkerTransportError("curve25519 worker is not available"));
        }

        return new Promise((resolve, reject) => {
            const id = this.#jobId++;
            this.#jobs.set(id, { resolve, reject });
            this.worker.postMessage({ id, methodName, args });
        });
    }

    terminate(): void {
        // Reject any in-flight jobs as a transport failure so the backend can
        // finish them on the fallback rather than leaving them pending forever.
        for (const job of this.#jobs.values()) {
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

    constructor(url: string, fallback: CurveBackend) {
        this.#fallback = fallback;
        try {
            const transport = new Curve25519Worker(url);
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
        this.#transport = null;

        // Latch: route subsequent operations straight to the fallback instead of
        // paying a doomed round-trip to a dead worker on every call.
        setCurveBackend(this.#fallback);
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
 * If the worker cannot be loaded, calls fall back to the local backend: the
 * bundled wasm in the default build, or a thrown error in the `worker-client`
 * build, which has no local wasm.
 */
export function startWorker(url: string): void {
    stopWorker();
    const backend = new WorkerCurveBackend(url, getLocalCurveBackend());
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

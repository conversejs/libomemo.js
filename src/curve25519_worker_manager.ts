import { CurveBackend, KeyPair, StartWorkerOptions, WorkerStatus } from "./types";
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

/**
 * How many consecutive timeouts, with no reply of any kind in between, mean the
 * worker is hung rather than briefly slow. A single timeout only fails its own
 * operation (which then completes on the fallback) and leaves the worker in place.
 * Reaching this count tears it down, so later operations go to the fallback.
 */
const MAX_CONSECUTIVE_TIMEOUTS = 2;

/**
 * How far past its own deadline a timer may fire before we stop trusting it.
 */
const TIMER_OVERSHOOT_GRACE_MS = 250;

/**
 * Backoff bounds for rebuilding a worker that failed. The delay doubles per
 * consecutive failure so a burst of operations cannot spawn a worker each, and
 * resets as soon as a worker completes a round trip.
 */
const WORKER_RESTART_BASE_DELAY_MS = 1_000;
const WORKER_RESTART_MAX_DELAY_MS = 60_000;

interface Job {
    resolve: (result: unknown) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout> | undefined;
    /** When this job's current timer is due to fire, for the overshoot check. */
    deadline: number;
    /** Whether the one-shot grace period for a blocked main thread has been used. */
    regranted: boolean;
}

interface WorkerResponse {
    id: number;
    ok?: boolean; // Explicit flag. Success must be asserted by the worker, not inferred.
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
 * operation error), as does a lone timeout. A worker-level failure (a crash, a
 * malformed reply, or repeated timeouts) rejects every pending job with a
 * WorkerTransportError and notifies the owner through `onTransportError`.
 */
class Curve25519Worker {
    #jobs = new Map<number, Job>();
    #jobId = 0;
    #dead = false;
    #consecutiveTimeouts = 0;
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
        const job = this.#take(data?.id);
        if (!job) return;

        // A reply of any shape proves the worker is alive and draining its queue.
        this.#consecutiveTimeouts = 0;

        if (data.ok === true) {
            job.resolve(data.result);
            return;
        }
        if (typeof data.error === "string" && data.error !== "") {
            job.reject(new Error(data.error)); // operation error: caller must not fall back
            return;
        }

        // Neither a well-formed success nor a well-formed failure.
        // Fail closed as a transport error.
        const malformed = new WorkerTransportError("curve25519 worker sent a malformed reply");
        job.reject(malformed);
        this.#fail(malformed);
    }

    // Remove a job from the pending set and cancel its timeout, returning it.
    #take(id: number | undefined): Job | undefined {
        if (id === undefined) return undefined;

        const job = this.#jobs.get(id);
        if (!job) return undefined;

        this.#jobs.delete(id);
        if (job.timer !== undefined) clearTimeout(job.timer);
        return job;
    }

    /**
     * A job whose reply did not arrive in time. This fails only that job, which the
     * backend then completes on the fallback. The worker itself is kept unless it
     * misses MAX_CONSECUTIVE_TIMEOUTS replies in a row. A single slow operation, or
     * a timer distorted by a blocked main thread, must not cost us the worker.
     */
    #onTimeout(id: number): void {
        const job = this.#jobs.get(id);
        if (!job) return;

        // The timer fired far later than it was due, so it measured a stalled main
        // thread rather than a stalled worker. Give the job one more full interval:
        // the reply may already be queued behind this callback.
        if (!job.regranted && Date.now() - job.deadline > TIMER_OVERSHOOT_GRACE_MS) {
            job.regranted = true;
            job.deadline = Date.now() + this.#timeoutMs;
            job.timer = setTimeout(() => this.#onTimeout(id), this.#timeoutMs);
            return;
        }

        this.#jobs.delete(id); // its timer has already fired, nothing to clear
        this.#consecutiveTimeouts++;
        job.reject(new WorkerTransportError("curve25519 worker timed out"));

        // Repeated timeouts with no reply in between: the worker really is hung, so
        // stop routing to it instead of making every later operation wait one out.
        if (this.#consecutiveTimeouts >= MAX_CONSECUTIVE_TIMEOUTS) {
            this.#fail(new WorkerTransportError("curve25519 worker timed out repeatedly"));
        }
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
            const timed = this.#timeoutMs > 0 && isFinite(this.#timeoutMs);
            const timer = timed
                ? setTimeout(() => this.#onTimeout(id), this.#timeoutMs)
                : undefined;
            this.#jobs.set(id, {
                resolve,
                reject,
                timer,
                deadline: timed ? Date.now() + this.#timeoutMs : Infinity,
                regranted: false,
            });
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
    readonly #url: string;
    readonly #fallback: CurveBackend;
    readonly #timeoutMs: number;
    readonly #onStatusChange: ((status: WorkerStatus) => void) | undefined;
    #transport: Curve25519Worker | null = null;
    #stopped = false;
    #restartAttempts = 0;
    #nextAttemptAt = 0;
    #offloaded = true; // Whether operations are currently reaching the worker.

    constructor(
        url: string,
        fallback: CurveBackend,
        timeoutMs: number,
        onStatusChange?: (status: WorkerStatus) => void
    ) {
        this.#url = url;
        this.#fallback = fallback;
        this.#timeoutMs = timeoutMs;
        // Assigned before #connect so a worker that fails to construct is reported.
        this.#onStatusChange = onStatusChange;
        this.#connect();
    }

    /**
     * Record where operations are running, announcing only genuine transitions.
     *
     * The consumer's callback is untrusted. It runs inside our dispatch path, so a
     * throw from it must not fail the operation that triggered it or surface as an
     * unhandled rejection.
     */
    #setOffloaded(offloaded: boolean, error?: Error): void {
        if (this.#offloaded === offloaded) return;
        this.#offloaded = offloaded;

        if (offloaded) {
            console.info(
                "libomemo.js: the curve25519 worker recovered; operations are offloaded again."
            );
        } else {
            console.error(
                "libomemo.js: the curve25519 worker failed; falling back to the local backend.",
                error
            );
        }

        try {
            this.#onStatusChange?.(error ? { offloaded, error } : { offloaded });
        } catch {
            // A broken status handler is the consumer's problem, not the crypto's.
        }
    }

    /**
     * Build the worker, or return null if we should not try right now.
     *
     * A failed worker is not permanent. `#nextAttemptAt` backs off so a burst of
     * operations cannot spawn a worker each, but a worker that was merely
     * unreachable for a while is picked up again on a later operation.
     * That recovery matters most in the `worker-client` build, whose
     * fallback throws by design. Without it, one transport failure would break every
     * subsequent OMEMO operation for the lifetime of the page.
     */
    #connect(): Curve25519Worker | null {
        if (this.#stopped) return null;
        if (Date.now() < this.#nextAttemptAt) return null;

        try {
            const transport = new Curve25519Worker(this.#url, this.#timeoutMs);
            transport.onTransportError = (err) => this.#onTransportError(err);
            this.#transport = transport;
            return transport;
        } catch (err) {
            // `new Worker()` throws synchronously for a malformed URL or a CSP block.
            this.#onTransportError(
                err instanceof WorkerTransportError ? err : new WorkerTransportError(String(err))
            );
            return null;
        }
    }

    #onTransportError(error: Error): void {
        this.#setOffloaded(false, error);

        // Back off before the next attempt, doubling per consecutive failure, so a
        // permanently broken worker URL costs one spawn per interval rather than one
        // per operation. #run resets this the moment a worker completes a round trip.
        this.#nextAttemptAt =
            Date.now() +
            Math.min(
                WORKER_RESTART_BASE_DELAY_MS * 2 ** this.#restartAttempts,
                WORKER_RESTART_MAX_DELAY_MS
            );
        this.#restartAttempts++;

        // Terminate the failed worker before dropping the reference. A timed-out
        // worker is still a live thread, and `onerror` fires for any uncaught error
        // without killing the worker, so neither case is self-cleaning.
        const transport = this.#transport;
        this.#transport = null;
        transport?.terminate();
    }

    async #run<T>(methodName: string, args: unknown[], local: () => Promise<T>): Promise<T> {
        const transport = this.#transport ?? this.#connect();
        if (!transport) return local();

        try {
            const result = (await transport.post(methodName, args)) as T;
            this.#onRoundTrip();
            return result;
        } catch (error) {
            // The worker died mid-call; #onTransportError has already dropped it and
            // scheduled the next attempt, so just complete this operation locally.
            if (error instanceof WorkerTransportError) return local();
            this.#onRoundTrip(); // an operation error also proves it is alive
            throw error; // operation error: propagate
        }
    }

    /** A completed round trip: this worker works, so clear the backoff and report it. */
    #onRoundTrip(): void {
        this.#restartAttempts = 0;
        this.#setOffloaded(true);
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
        this.#stopped = true; // an explicit stop must not be undone by #connect
        this.#transport?.terminate();
        this.#transport = null;
    }
}

let activeWorkerBackend: WorkerCurveBackend | null = null;

/**
 * Offload curve operations to the Web Worker at `url` (typically the bundled
 * `dist/libomemo-worker.js`). Subsequent OMEMO crypto runs off the main thread.
 * If the worker cannot be loaded, or a call does not get a reply within
 * `options.timeout` ms, that call falls back to the local backend: the bundled wasm
 * in the default build, or a thrown error in the `worker-client` build, which has no
 * local wasm.
 *
 * A failure is not permanent. A single timeout fails only its own operation; the
 * worker is dropped after repeated timeouts or a crash, and is then rebuilt
 * automatically on a later operation (with backoff), so a transient outage does not
 * disable offloading, or, in the `worker-client` build, all cryptography, for the
 * lifetime of the page. `stopWorker()` is the only permanent stop.
 *
 * Because that movement is invisible from the outside, and in the default build it
 * means private-key operations have moved onto the main thread, pass
 * `options.onStatusChange` to observe it rather than relying on the console.
 *
 * @param url      URL of the worker script. It receives raw private keys, so it must
 *                 be a trusted same-origin, CSP-permitted script, not a URL derived
 *                 from remote input.
 * @param options.timeout  Per-operation reply timeout in milliseconds
 *                 (default 10000). Pass 0 to disable the timeout.
 * @param options.onStatusChange  Called whenever operations start or stop running in
 *                 the worker. See {@link WorkerStatus}.
 */
export function startWorker(url: string, options: StartWorkerOptions = {}): void {
    stopWorker();
    const timeoutMs = options.timeout ?? DEFAULT_WORKER_TIMEOUT_MS;
    const backend = new WorkerCurveBackend(
        url,
        getLocalCurveBackend(),
        timeoutMs,
        options.onStatusChange
    );
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

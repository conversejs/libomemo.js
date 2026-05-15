interface Job {
    onsuccess: (result: unknown) => void;
    onerror: (error: Error) => void;
}

interface WorkerResponse {
    id: number;
    result?: unknown;
    error?: string;
}

interface KeyPair {
    pubKey: ArrayBuffer;
    privKey: ArrayBuffer;
}

interface CurveAsyncMethods {
    generateKeyPair(): Promise<KeyPair>;
    createKeyPair(privKey: ArrayBuffer): Promise<KeyPair>;
    calculateAgreement(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer>;
    verifySignature(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void>;
    calculateSignature(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer>;
}

let workerInstance: Curve25519Worker | null = null;

class Curve25519Worker implements CurveAsyncMethods {
    #jobs: Record<number, Job> = {};
    #jobId = 0;
    worker: Worker;

    constructor(url: string) {
        this.worker = new Worker(url);
        this.worker.onmessage = (e: MessageEvent<WorkerResponse>) => this.#onMessage(e);
    }

    #onMessage(e: MessageEvent<WorkerResponse>): void {
        const job = this.#jobs[e.data.id];
        if (e.data.error && typeof job.onerror === "function") {
            job.onerror(new Error(e.data.error));
        } else if (typeof job.onsuccess === "function") {
            job.onsuccess(e.data.result!);
        }
        delete this.#jobs[e.data.id];
    }

    #postMessage(methodName: string, args: unknown[]): Promise<unknown> {
        return new Promise((resolve, reject) => {
            this.#jobs[this.#jobId] = { onsuccess: resolve, onerror: reject };
            this.worker.postMessage({ id: this.#jobId, methodName, args });
            this.#jobId++;
        });
    }

    generateKeyPair(): Promise<KeyPair> {
        const privKey = crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer;
        return this.createKeyPair(privKey);
    }

    createKeyPair(privKey: ArrayBuffer): Promise<KeyPair> {
        return this.#postMessage("createKeyPair", [privKey]) as Promise<KeyPair>;
    }

    calculateAgreement(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#postMessage("calculateAgreement", [pubKey, privKey]) as Promise<ArrayBuffer>;
    }

    calculateSignature(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        return this.#postMessage("calculateSignature", [privKey, message]) as Promise<ArrayBuffer>;
    }

    verifySignature(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void> {
        return this.#postMessage("verifySignature", [pubKey, msg, sig]) as Promise<void>;
    }
}

export function startWorker(url: string): void {
    stopWorker();
    const worker = new Curve25519Worker(url);
    workerInstance = worker;
}

export function stopWorker(): void {
    if (workerInstance) {
        workerInstance.worker.terminate();
        workerInstance = null;
    }
}

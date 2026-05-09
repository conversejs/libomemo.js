import { Curve } from "./Curve.js";

let workerInstance = null;
let origCurveAsync = null;

class Curve25519Worker {
    #jobs = {};
    #jobId = 0;

    constructor(url) {
        this.worker = new Worker(url);
        this.worker.onmessage = (e) => this.#onMessage(e);
    }

    #onMessage(e) {
        const job = this.#jobs[e.data.id];
        if (e.data.error && typeof job.onerror === "function") {
            job.onerror(new Error(e.data.error));
        } else if (typeof job.onsuccess === "function") {
            job.onsuccess(e.data.result);
        }
        delete this.#jobs[e.data.id];
    }

    #postMessage(methodName, args) {
        return new Promise((resolve, reject) => {
            this.#jobs[this.#jobId] = { onsuccess: resolve, onerror: reject };
            this.worker.postMessage({ id: this.#jobId, methodName, args });
            this.#jobId++;
        });
    }

    keyPair(privKey) {
        return this.#postMessage("keyPair", [privKey]);
    }

    sharedSecret(pubKey, privKey) {
        return this.#postMessage("sharedSecret", [pubKey, privKey]);
    }

    sign(privKey, message) {
        return this.#postMessage("sign", [privKey, message]);
    }

    verify(pubKey, message, sig) {
        return this.#postMessage("verify", [pubKey, message, sig]);
    }
}

export function startWorker(url) {
    stopWorker();
    origCurveAsync = Curve.async;
    const worker = new Curve25519Worker(url);
    workerInstance = worker;
    // Replace Curve.async with the worker proxy
    Curve.async = Promise.resolve(worker);
}

export function stopWorker() {
    if (workerInstance) {
        workerInstance.worker.terminate();
        workerInstance = null;
        Curve.async = origCurveAsync;
        origCurveAsync = null;
    }
}

(function() {

'use strict';

// I am the...workee?
const origCurve25519 = Internal.curve25519_async;

Internal.startWorker = function(url) {
    Internal.stopWorker(); // there can be only one
    Internal.curve25519_async = new Curve25519Worker(url);
};

Internal.stopWorker = function() {
    if (Internal.curve25519_async instanceof Curve25519Worker) {
        const worker = Internal.curve25519_async.worker;
        Internal.curve25519_async = origCurve25519;
        worker.terminate();
    }
};

libsignal.worker = {
  startWorker: Internal.startWorker,
  stopWorker: Internal.stopWorker,
};

})();

class Curve25519Worker {

    constructor (url) {
        this.jobs = {};
        this.jobId = 0;
        this.worker = new Worker(url);
        this.worker.onmessage = (e) => this.onMessage(e);
    }

    onMessage (e) {
        const job = this.jobs[e.data.id];
        if (e.data.error && typeof job.onerror === 'function') {
            job.onerror(new Error(e.data.error));
        } else if (typeof job.onsuccess === 'function') {
            job.onsuccess(e.data.result);
        }
        delete this.jobs[e.data.id];
    }

    postMessage (methodName, args) {
        return new Promise((resolve, reject) => {
          this.jobs[this.jobId] = { onsuccess: resolve, onerror: reject };
          this.worker.postMessage({ id: this.jobId, methodName: methodName, args: args });
          this.jobId++;
        });
    }

    keyPair (privKey) {
        return this.postMessage('keyPair', [privKey]);
    }

    sharedSecret (pubKey, privKey) {
        return this.postMessage('sharedSecret', [pubKey, privKey]);
    }

    sign (privKey, message) {
        return this.postMessage('sign', [privKey, message]);
    }

    verify (pubKey, message, sig) {
        return this.postMessage('verify', [pubKey, message, sig]);
    }
}

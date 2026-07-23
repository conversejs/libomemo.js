/**
 * Stand-in for the wasm-backed {@link Curve25519}, substituted for `./curve` in
 * the `worker-client` build (see rollup.config.js). That build ships no
 * WebAssembly and every curve operation must run in the worker. This stub is the
 * local backend there, so if any operation reaches it, it means no worker is
 * available, which is a usage error we surface (via Promise.reject);
 *
 * The class only needs the methods LocalCurveBackend calls; it deliberately does
 * not import the compiled module, which is what keeps the wasm out of this build.
 */
const NO_LOCAL_WASM =
    "libomemo.js/worker-client runs no cryptography on the main thread: call " +
    "startWorker(url) with a reachable worker script before any OMEMO operation.";

export class Curve25519 {
    createKeyPair(): Promise<never> {
        return Promise.reject(new Error(NO_LOCAL_WASM));
    }

    ECDHE(): Promise<never> {
        return Promise.reject(new Error(NO_LOCAL_WASM));
    }

    Ed25519Sign(): Promise<never> {
        return Promise.reject(new Error(NO_LOCAL_WASM));
    }

    verifySignature(): Promise<never> {
        return Promise.reject(new Error(NO_LOCAL_WASM));
    }

    curvePubKeyToEd25519PubKey(): Promise<never> {
        return Promise.reject(new Error(NO_LOCAL_WASM));
    }

    ed25519PubKeyToCurvePubKey(): Promise<never> {
        return Promise.reject(new Error(NO_LOCAL_WASM));
    }
}

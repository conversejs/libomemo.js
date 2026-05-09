// Worker curve25519 operations - standalone Web Worker entry point
// This file is bundled separately as an IIFE for Web Worker usage
import { getModule, createCurve25519, createCurve25519Async } from "./curve25519_wrapper.js";

getModule().then((Module) => {
    const curve25519_async = createCurve25519Async(createCurve25519(Module));

    self.onmessage = (e) => {
        curve25519_async[e.data.methodName]
            .apply(null, e.data.args)
            .then((result) => {
                postMessage({ id: e.data.id, result });
            })
            .catch((error) => {
                postMessage({ id: e.data.id, error: error.message });
            });
    };
});

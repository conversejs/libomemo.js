import { Curve25519 } from "./curve";

interface WorkerMessage {
    id: number;
    methodName: keyof Curve25519;
    args: unknown[];
}

const curve = new Curve25519();

const ALLOWED_METHODS = new Set<keyof Curve25519>([
    "generateKeyPair",
    "createKeyPair",
    "calculateAgreement",
    "calculateSignature",
    "verifySignature",
]);

self.onmessage = (e: MessageEvent<WorkerMessage>) => {
    const { id, methodName, args } = e.data;

    if (!ALLOWED_METHODS.has(methodName)) {
        postMessage({ id, error: "Unsupported method." });
        return;
    }

    const method = curve[methodName];
    if (typeof method !== "function") {
        postMessage({ id, error: "Unsupported method." });
        return;
    }

    Promise.resolve((method as (...a: unknown[]) => Promise<unknown>)(...args))
        .then((result: unknown) => {
            postMessage({ id, result });
        })
        .catch((error: Error) => {
            postMessage({ id, error: error.message });
        });
};

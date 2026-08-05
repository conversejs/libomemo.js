import { Curve25519 } from "./curve";

interface WorkerMessage {
    id: number;
    methodName: keyof Curve25519;
    args: unknown[];
}

const curve = new Curve25519();

const ALLOWED_METHODS = new Set<keyof Curve25519>([
    "createKeyPair",
    "calculateAgreement",
    "calculateSignature",
    "verifySignature",
    "curvePubKeyToEd25519PubKey",
    "ed25519PubKeyToCurvePubKey",
]);

/**
 * Reduce a thrown value to a non-empty message string.
 */
function toErrorMessage(error: unknown): string {
    if (error instanceof Error && error.message) return error.message;
    if (typeof error === "string" && error) return error;
    return "curve25519 worker operation failed";
}

self.onmessage = (e: MessageEvent<WorkerMessage>) => {
    const { id, methodName, args } = e.data;

    if (!ALLOWED_METHODS.has(methodName)) {
        postMessage({ id, ok: false, error: "Unsupported method." });
        return;
    }

    const method = curve[methodName];
    if (typeof method !== "function") {
        postMessage({ id, ok: false, error: "Unsupported method." });
        return;
    }

    Promise.resolve((method.bind(curve) as (...a: unknown[]) => Promise<unknown>)(...args))
        .then((result: unknown) => {
            // `ok: true` is what makes success explicit rather than inferred from
            // the absence of an error. See the manager's #onMessage.
            postMessage({ id, ok: true, result });
        })
        .catch((error: unknown) => {
            postMessage({ id, ok: false, error: toErrorMessage(error) });
        });
};

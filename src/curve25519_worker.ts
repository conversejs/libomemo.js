import { Curve25519 } from "./curve";

interface WorkerMessage {
    id: number;
    methodName: keyof Curve25519;
    args: unknown[];
}

const curve = new Curve25519();

self.onmessage = (e: MessageEvent<WorkerMessage>) => {
    const method = curve[e.data.methodName];
    Promise.resolve(method(...(e.data.args as [any, any, any])))
        .then((result: unknown) => {
            postMessage({ id: e.data.id, result });
        })
        .catch((error: Error) => {
            postMessage({ id: e.data.id, error: error.message });
        });
};

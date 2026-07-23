import { expect } from "chai";
import { Curve25519 } from "../src/curve.worker-client.js";

/**
 * The worker-client build swaps the wasm-backed curve for this stub (see
 * stubCurvePlugin in rollup.config.js): it runs no cryptography on the main
 * thread, so every operation must reject and tell the caller to start a worker
 * first. That rejection is the entire local-side contract of the worker-client
 * build, so pin it here rather than leave the message to rot untested.
 */
describe("worker-client curve stub (no local wasm)", function () {
    const curve = new Curve25519();

    const operations: { name: string; call: () => Promise<unknown> }[] = [
        { name: "createKeyPair", call: () => curve.createKeyPair() },
        { name: "ECDHE", call: () => curve.ECDHE() },
        { name: "Ed25519Sign", call: () => curve.Ed25519Sign() },
        { name: "verifySignature", call: () => curve.verifySignature() },
        { name: "curvePubKeyToEd25519PubKey", call: () => curve.curvePubKeyToEd25519PubKey() },
        { name: "ed25519PubKeyToCurvePubKey", call: () => curve.ed25519PubKeyToCurvePubKey() },
    ];

    for (const { name, call } of operations) {
        it(`${name} rejects, directing the caller to startWorker`, async function () {
            let caught: Error | undefined;
            try {
                await call();
            } catch (e) {
                caught = e as Error;
            }
            expect(caught, `${name} should have rejected`).to.be.instanceOf(Error);
            // The message is the actionable contract: it must point at startWorker.
            expect(caught?.message).to.include("startWorker");
        });
    }
});

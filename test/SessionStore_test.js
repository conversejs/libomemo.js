import { assert } from "chai";
import { OMEMOAddress } from "../src/index.js";
import { assertEqualArrayBuffers } from "./utils.js";

export function testSessionStore(store) {
    const number = "+5558675309";
    const testRecord = "an opaque string";
    describe("SessionStore", function () {
        describe("storeSession", function () {
            const address = new OMEMOAddress(number, 1);
            it("stores sessions encoded as strings", async function () {
                await store.storeSession(address.toString(), testRecord);
                const record = await store.loadSession(address.toString());
                assert.strictEqual(record, testRecord);
            });

            it("stores sessions encoded as array buffers", async function () {
                const testRecord = new Uint8Array([1, 2, 3]).buffer;
                await store.storeSession(address.toString(), testRecord);
                const record = await store.loadSession(address.toString());
                assertEqualArrayBuffers(testRecord, record);
            });
        });

        describe("loadSession", function () {
            it("returns sessions that exist", async function () {
                const address = new OMEMOAddress(number, 1);
                const testRecord = "an opaque string";
                await store.storeSession(address.toString(), testRecord);
                const record = await store.loadSession(address.toString());
                assert.strictEqual(record, testRecord);
            });

            it("returns undefined for sessions that do not exist", async function () {
                const address = new OMEMOAddress(number, 2);
                const record = await store.loadSession(address.toString());
                assert.isUndefined(record);
            });
        });

        describe("removeSession", function () {
            it("deletes sessions", async function () {
                const address = new OMEMOAddress(number, 1);
                before(() => store.storeSession(address.toString(), testRecord));

                await store.removeSession(address.toString());
                const record = await store.loadSession(address.toString());
                assert.isUndefined(record);
            });
        });

        describe("removeAllSessions", function () {
            it("removes all sessions for a number", async function () {
                const devices = [1, 2, 3].map((deviceId) => {
                    const address = new OMEMOAddress(number, deviceId);
                    return address.toString();
                });

                await Promise.all(
                    devices.map((encodedNumber) =>
                        store.storeSession(encodedNumber, testRecord + encodedNumber)
                    )
                );

                await store.removeAllSessions(number);
                const records = await Promise.all(devices.map(store.loadSession.bind(store)));
                for (const i in records) {
                    if (!Object.prototype.hasOwnProperty.call(records, i)) {
                        continue;
                    }
                    assert.isUndefined(records[i]);
                }
            });
        });
    });
}

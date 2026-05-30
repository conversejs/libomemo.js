import { assert } from "chai";
import { OMEMOAddress } from "../src/index.js";

describe("OMEMOAddress", function () {
    const name = "name";
    const deviceId = 42;
    const string = "name.42";
    describe("getName", function () {
        it("returns the name", function () {
            const address = new OMEMOAddress(name, 1);
            assert.strictEqual(name, address.getName());
        });
    });
    describe("getDeviceId", function () {
        it("returns the deviceId", function () {
            const address = new OMEMOAddress(name, deviceId);
            assert.strictEqual(deviceId, address.getDeviceId());
        });
    });
    describe("toString", function () {
        it("returns the address", function () {
            const address = new OMEMOAddress(name, deviceId);
            assert.strictEqual(string, address.toString());
        });
    });
    describe("fromString", function () {
        it("throws on a bad inputs", function () {
            (["", null, {}] as (string | null | object)[]).forEach(function (input) {
                assert.throws(function () {
                    OMEMOAddress.fromString(input as string);
                });
            });
        });
        it("constructs the address", function () {
            const address = OMEMOAddress.fromString(string);
            assert.strictEqual(deviceId, address.getDeviceId());
            assert.strictEqual(name, address.getName());
        });
        it("constructs the address from a JID", function () {
            const jid = "alice@example.com";
            const jidString = "alice@example.com.42";
            const address = OMEMOAddress.fromString(jidString);
            assert.strictEqual(42, address.getDeviceId());
            assert.strictEqual(jid, address.getName());
        });
        it("constructs the address from a JID with resource", function () {
            const jid = "alice@example.com/phone";
            const jidString = "alice@example.com/phone.7";
            const address = OMEMOAddress.fromString(jidString);
            assert.strictEqual(7, address.getDeviceId());
            assert.strictEqual(jid, address.getName());
        });
        it("round-trips JID addresses correctly", function () {
            const jid = "bob@xmpp.server.org";
            const address = new OMEMOAddress(jid, 3);
            const str = address.toString();
            const parsed = OMEMOAddress.fromString(str);
            assert.strictEqual(jid, parsed.getName());
            assert.strictEqual(3, parsed.getDeviceId());
        });
    });
});

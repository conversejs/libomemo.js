import { assert } from "chai";
import { internalCrypto } from "../src/crypto.js";
import { SignalProtocolAddress } from "../src/index.js";
import { assertEqualArrayBuffers } from "./utils.js";

export function testPreKeyStore(store) {
    const number = "+5558675309";
    let testKey;

    describe("PreKeyStore", function () {
        before(async function () {
            testKey = await internalCrypto.createKeyPair();
        });

        describe("storePreKey", function () {
            it("stores prekeys", async function () {
                const address = new SignalProtocolAddress(number, 1);
                await store.storePreKey(address.toString(), testKey);
                const key = await store.loadPreKey(address.toString());
                assertEqualArrayBuffers(key.pubKey, testKey.pubKey);
                assertEqualArrayBuffers(key.privKey, testKey.privKey);
            });
        });

        describe("loadPreKey", function () {
            it("returns prekeys that exist", async function () {
                const address = new SignalProtocolAddress(number, 1);
                await store.storePreKey(address.toString(), testKey);
                const key = await store.loadPreKey(address.toString());
                assertEqualArrayBuffers(key.pubKey, testKey.pubKey);
                assertEqualArrayBuffers(key.privKey, testKey.privKey);
            });

            it("returns undefined for prekeys that do not exist", async function () {
                const address = new SignalProtocolAddress(number, 2);
                const key = await store.loadPreKey(address.toString());
                assert.isUndefined(key);
            });
        });

        describe("removePreKey", function () {
            it("deletes prekeys", async function () {
                const address = new SignalProtocolAddress(number, 2);
                before(() => store.storePreKey(address.toString(), testKey));
                store.removePreKey(address.toString());
                const key = await store.loadPreKey(address.toString());
                assert.isUndefined(key);
            });
        });
    });
}

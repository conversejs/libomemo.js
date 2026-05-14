import { assert } from "chai";
import { internalCrypto } from "../src/crypto.js";
import type { KeyPair } from "../src/types.js";
import { assertEqualArrayBuffers } from "./utils.js";
import { OMEMOStore } from "../src/session/types.js";

export function testSignedPreKeyStore(store: OMEMOStore): void {
    describe("SignedPreKeyStore", function () {
        let testKey: KeyPair;
        before(async () => {
            testKey = await internalCrypto.createKeyPair();
        });

        describe("storeSignedPreKey", function () {
            it("stores signed prekeys", async function () {
                await store.storeSignedPreKey(3, testKey);
                const key = await store.loadSignedPreKey(3);
                assertEqualArrayBuffers(key!.keyPair.pubKey, testKey.pubKey);
                assertEqualArrayBuffers(key!.keyPair.privKey, testKey.privKey);
            });
        });

        describe("loadSignedPreKey", function () {
            it("returns prekeys that exist", async function () {
                await store.storeSignedPreKey(1, testKey);
                const key = await store.loadSignedPreKey(1);
                assertEqualArrayBuffers(key!.keyPair.pubKey, testKey.pubKey);
                assertEqualArrayBuffers(key!.keyPair.privKey, testKey.privKey);
            });

            it("returns undefined for prekeys that do not exist", async function () {
                await store.storeSignedPreKey(1, testKey);
                const key = await store.loadSignedPreKey(2);
                assert.isUndefined(key);
            });
        });

        describe("removeSignedPreKey", function () {
            it("deletes signed prekeys", async function () {
                before(() => store.storeSignedPreKey(4, testKey));
                await store.removeSignedPreKey(4);
                const key = await store.loadSignedPreKey(4);
                assert.isUndefined(key);
            });
        });
    });
}

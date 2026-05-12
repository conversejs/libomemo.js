import { assert } from "chai";
import { internalCrypto } from "../src/crypto.js";
import { OMEMOAddress } from "../src/index.js";
import { getRandomBytes } from "../src/crypto.js";
import { assertEqualArrayBuffers } from "./utils.js";

export function testIdentityKeyStore(store, registrationId, identityKey) {
    const number = "+5558675309";
    const address = new OMEMOAddress("+5558675309", 1);
    let testKey;

    describe("IdentityKeyStore", function () {
        before(async () => {
            testKey = await internalCrypto.createKeyPair();
        });

        describe("getLocalRegistrationId", function () {
            it("retrieves my registration id", async function () {
                const reg = await store.getLocalRegistrationId();
                assert.strictEqual(reg, registrationId);
            });
        });

        describe("getIdentityKeyPair", function () {
            it("retrieves my identity key", async function () {
                const key = await store.getIdentityKeyPair();
                assertEqualArrayBuffers(key.pubKey, identityKey.pubKey);
                assertEqualArrayBuffers(key.privKey, identityKey.privKey);
            });
        });

        describe("saveIdentity", function () {
            it("stores identity keys", async function () {
                await store.saveIdentity(address.toString(), testKey.pubKey);
                const key = await store.loadIdentityKey(number);
                assertEqualArrayBuffers(key, testKey.pubKey);
            });
        });

        describe("isTrustedIdentity", function () {
            it("returns true if a key is trusted", async function () {
                await store.saveIdentity(address.toString(), testKey.pubKey);
                const trusted = await store.isTrustedIdentity(number, testKey.pubKey);
                assert.isTrue(trusted);
            });
            it("returns false if a key is untrusted", async function () {
                const newIdentity = getRandomBytes(33);
                await store.saveIdentity(address.toString(), testKey.pubKey);
                const trusted = await store.isTrustedIdentity(number, newIdentity);
                assert.isFalse(trusted);
            });
        });
    });
}

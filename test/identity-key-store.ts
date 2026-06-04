import { assert } from "chai";
import { internalCrypto } from "../src/crypto.js";
import { OMEMOAddress } from "../src/index.js";
import { getRandomBytes } from "../src/crypto.js";
import type { KeyPair } from "../src/types.js";
import { assertEqualArrayBuffers } from "./utils.js";
import { OMEMOStore, Direction } from "../src/session/types.js";

export function testIdentityKeyStore(
    store: OMEMOStore,
    registrationId: number,
    identityKey: KeyPair
): void {
    const address = new OMEMOAddress("romeo@montague.lit", 1);
    let testKey: KeyPair;

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
                assert.isNotNull(key);
                assertEqualArrayBuffers(key!.pubKey, identityKey.pubKey);
                assertEqualArrayBuffers(key!.privKey, identityKey.privKey);
            });
        });

        describe("saveIdentity", function () {
            it("stores identity keys", async function () {
                await store.saveIdentity(address.toString(), testKey.pubKey);
                const key = await store.loadIdentityKey(address.toString());
                assertEqualArrayBuffers(key!, testKey.pubKey);
            });
        });

        describe("isTrustedIdentity", function () {
            it("returns true if a key is trusted", async function () {
                await store.saveIdentity(address.toString(), testKey.pubKey);
                const trusted = await store.isTrustedIdentity(
                    address.toString(),
                    testKey.pubKey,
                    Direction.SENDING
                );
                assert.isTrue(trusted);
            });
            it("returns false if a key is untrusted", async function () {
                const newIdentity = getRandomBytes(33);
                await store.saveIdentity(address.toString(), testKey.pubKey);
                const trusted = await store.isTrustedIdentity(
                    address.toString(),
                    newIdentity,
                    Direction.SENDING
                );
                assert.isFalse(trusted);
            });
        });
    });
}

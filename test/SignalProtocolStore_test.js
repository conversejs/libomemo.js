import { getRandomBytes } from "../src/crypto.js";
import SignalProtocolStore from "./InMemorySignalProtocolStore.js";
import { testIdentityKeyStore } from "./IdentityKeyStore_test.js";
import { testPreKeyStore } from "./PreKeyStore_test.js";
import { testSignedPreKeyStore } from "./SignedPreKeyStore_test.js";
import { testSessionStore } from "./SessionStore_test.js";

describe("SignalProtocolStore", function () {
    const store = new SignalProtocolStore();
    const registrationId = 1337;
    const identityKey = {
        pubKey: getRandomBytes(33),
        privKey: getRandomBytes(32),
    };
    before(function () {
        store.put("registrationId", registrationId);
        store.put("identityKey", identityKey);
    });
    testIdentityKeyStore(store, registrationId, identityKey);
    testPreKeyStore(store);
    testSignedPreKeyStore(store);
    testSessionStore(store);
});

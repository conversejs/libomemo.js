import { getRandomBytes } from "../src/crypto";
import InMemoryStore from "../src/session/store";
import { testIdentityKeyStore } from "./identity-key-store";
import { testPreKeyStore } from "./prekey-store";
import { testSignedPreKeyStore } from "./signed-prekey-store";
import { testSessionStore } from "./session-store";
import type { KeyPair } from "../src/types";

describe("OMEMOStore", function () {
    const store = new InMemoryStore();
    const registrationId = 1337;
    const identityKey: KeyPair = {
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

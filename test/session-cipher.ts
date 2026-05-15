import { assert } from "chai";
import { SessionBuilder, SessionCipher, OMEMOAddress, util } from "../src/index";
import { SessionRecord } from "../src/session/record";
import { internalCrypto } from "../src/crypto";
import { loadProtocolMessages, loadPushMessages } from "../src/protobufs";
import { generateIdentity, generatePreKeyBundle } from "./utils";
import { SendMessageData, ReceiveMessageData, TestVectors, TestVectorEntry } from "./testvectors";
import { BaseKeyType, KeyPair } from "../src/types";
import { OMEMOStore } from "../src/session/types";
import InMemoryStore from "../src/session/store";

enum PushMessageFlags {
    END_SESSION = 1,
}

interface PushMessageContentDecoded {
    body?: string;
    flags?: number;
}

interface PushMessageContentProto {
    create(data?: { body?: string; flags?: number }): Record<string, unknown>;
    encode(data: Record<string, unknown>): { finish(): Uint8Array };
    decode(data: Uint8Array): PushMessageContentDecoded;
}

interface IncomingPushMessageSignalProto {
    Type: { CIPHERTEXT: 1; PREKEY_BUNDLE: 3 };
}

interface PushMessagesTyped {
    IncomingPushMessageSignal: IncomingPushMessageSignalProto;
    PushMessageContent: PushMessageContentProto;
}

describe("SessionCipher", function () {
    describe("getRemoteRegistrationId", function () {
        const store = new InMemoryStore();
        const registrationId = 1337;
        const address = new OMEMOAddress("foo", 1);
        const sessionCipher = new SessionCipher(store, address.toString());

        describe("when an open record exists", function () {
            before(async () => {
                const record = new SessionRecord();
                const session = {
                    registrationId: registrationId,
                    currentRatchet: {
                        rootKey: new ArrayBuffer(32),
                        lastRemoteEphemeralKey: new ArrayBuffer(32),
                        previousCounter: 0,
                        ephemeralKeyPair: {
                            privKey: new ArrayBuffer(32),
                            pubKey: new ArrayBuffer(32),
                        },
                    },
                    indexInfo: {
                        baseKey: new ArrayBuffer(32),
                        baseKeyType: BaseKeyType.OURS,
                        closed: -1,
                        remoteIdentityKey: new ArrayBuffer(32),
                    },
                    oldRatchetList: [],
                    ephemeralKey: new ArrayBuffer(32),
                };
                record.updateSessionState(session);
                store.storeSession(address.toString(), record.serialize());
            });

            it("returns a valid registrationId", async function () {
                const value = await sessionCipher.getRemoteRegistrationId();
                assert.strictEqual(value, registrationId);
            });
        });

        describe("when a record does not exist", function () {
            it("returns undefined", async function () {
                const sessionCipher = new SessionCipher(store, "bar.1");
                const value = await sessionCipher.getRemoteRegistrationId();
                assert.isUndefined(value);
            });
        });
    });

    describe("hasOpenSession", function () {
        const store = new InMemoryStore();
        const address = new OMEMOAddress("foo", 1);
        const sessionCipher = new SessionCipher(store, address.toString());

        describe("open session exists", function () {
            before(async function () {
                const record = new SessionRecord();
                const session = {
                    registrationId: 1337,
                    currentRatchet: {
                        rootKey: new ArrayBuffer(32),
                        lastRemoteEphemeralKey: new ArrayBuffer(32),
                        previousCounter: 0,
                        ephemeralKeyPair: {
                            privKey: new ArrayBuffer(32),
                            pubKey: new ArrayBuffer(32),
                        },
                    },
                    indexInfo: {
                        baseKey: new ArrayBuffer(32),
                        baseKeyType: BaseKeyType.OURS,
                        remoteIdentityKey: new ArrayBuffer(32),
                        closed: -1,
                    },
                    oldRatchetList: [],
                    ephemeralKeyPair: {
                        privKey: new ArrayBuffer(32),
                        pubKey: new ArrayBuffer(32),
                    },
                };
                record.updateSessionState(session);
                store.storeSession(address.toString(), record.serialize());
            });

            it("returns true", async function () {
                const value = await sessionCipher.hasOpenSession();
                assert.isTrue(value);
            });
        });

        describe("no open session exists", function () {
            before(async function () {
                const record = new SessionRecord();
                store.storeSession(address.toString(), record.serialize());
            });

            it("returns false", async function () {
                const value = await sessionCipher.hasOpenSession();
                assert.isFalse(value);
            });
        });
        describe("when there is no session", function () {
            it("returns false", async function () {
                const value = await sessionCipher.hasOpenSession();
                assert.isFalse(value);
            });
        });
    });

    async function setupReceiveStep(
        store: OMEMOStore,
        data: ReceiveMessageData,
        privKeyQueue: ArrayBuffer[]
    ) {
        if (data.newEphemeralKey !== undefined) {
            privKeyQueue.push(data.newEphemeralKey);
        }

        if (data.ourIdentityKey === undefined) {
            return Promise.resolve();
        }

        const keyPair = await internalCrypto.createKeyPair(data.ourIdentityKey);
        store.put("identityKey", keyPair);

        const signedKeyPair = await internalCrypto.createKeyPair(data.ourSignedPreKey);
        await store.storeSignedPreKey(data.signedPreKeyId, signedKeyPair);

        if (data.ourPreKey !== undefined) {
            const keyPair = await internalCrypto.createKeyPair(data.ourPreKey);
            await store.storePreKey(data.preKeyId, keyPair);
        }
    }

    function getPaddedMessageLength(messageLength: number) {
        const messageLengthWithTerminator = messageLength + 1;
        let messagePartCount = Math.floor(messageLengthWithTerminator / 160);

        if (messageLengthWithTerminator % 160 !== 0) {
            messagePartCount++;
        }

        return messagePartCount * 160;
    }

    function pad(plaintext: ArrayBuffer | Uint8Array<ArrayBufferLike>): ArrayBuffer {
        const paddedPlaintext = new Uint8Array(
            getPaddedMessageLength(plaintext.byteLength + 1) - 1
        );
        paddedPlaintext.set(new Uint8Array(plaintext));
        paddedPlaintext[plaintext.byteLength] = 0x80;

        return paddedPlaintext.buffer;
    }

    function unpad(paddedPlaintext: ArrayBuffer | Uint8Array) {
        paddedPlaintext = new Uint8Array(paddedPlaintext);
        let plaintext: Uint8Array = new Uint8Array();

        for (let i = paddedPlaintext.length - 1; i >= 0; i--) {
            if (paddedPlaintext[i] == 0x80) {
                plaintext = paddedPlaintext.subarray(0, i);
                break;
            } else if (paddedPlaintext[i] !== 0x00) {
                throw new Error("Invalid padding");
            }
        }

        if (!plaintext.length) {
            console.error("Could not unpad", paddedPlaintext);
            throw new Error("Could not unpad");
        }

        return plaintext;
    }

    async function doReceiveStep(
        store: OMEMOStore,
        data: ReceiveMessageData,
        privKeyQueue: ArrayBuffer[],
        address: OMEMOAddress
    ) {
        await setupReceiveStep(store, data, privKeyQueue);

        let plaintext: ArrayBuffer | Uint8Array<ArrayBufferLike> | undefined;
        const sessionCipher = new SessionCipher(store, address);
        const pushMessages = (await loadPushMessages()) as unknown as PushMessagesTyped;
        const Type = pushMessages.IncomingPushMessageSignal.Type;

        if (data.type == Type.CIPHERTEXT) {
            plaintext = await sessionCipher
                .decryptWhisperMessage(data.message, "binary")
                .then(unpad);
        } else if (data.type == Type.PREKEY_BUNDLE) {
            plaintext = await sessionCipher
                .decryptPreKeyWhisperMessage(data.message, "binary")
                .then(unpad);
        } else {
            throw new Error("Unknown data type in test vector");
        }

        if (!plaintext) throw new Error("Could not decrypt");

        const content = pushMessages.PushMessageContent.decode(new Uint8Array(plaintext));
        if (data.expectTerminateSession) {
            if (content.flags == PushMessageFlags.END_SESSION) {
                return true;
            } else {
                return false;
            }
        }
        return content.body == data.expectedSmsText;
    }

    async function setupSendStep(
        store: OMEMOStore,
        data: SendMessageData,
        privKeyQueue: ArrayBuffer[]
    ) {
        if (data.registrationId !== undefined) {
            store.put("registrationId", data.registrationId);
        }
        if (data.ourBaseKey !== undefined) {
            privKeyQueue.push(data.ourBaseKey);
        }
        if (data.ourEphemeralKey !== undefined) {
            privKeyQueue.push(data.ourEphemeralKey);
        }

        if (data.ourIdentityKey !== undefined) {
            const keyPair = await internalCrypto.createKeyPair(data.ourIdentityKey);
            store.put("identityKey", keyPair);
        }
        return Promise.resolve();
    }

    async function doSendStep(
        store: OMEMOStore,
        data: SendMessageData,
        privKeyQueue: ArrayBuffer[],
        address: OMEMOAddress
    ) {
        await setupSendStep(store, data, privKeyQueue);
        if (data.getKeys !== undefined) {
            const deviceObject = {
                identityKey: data.getKeys.identityKey,
                signedPreKey: data.getKeys.devices[0].signedPreKey,
                encodedNumber: address.toString(),
                preKey: data.getKeys.devices[0].preKey,
                registrationId: data.getKeys.devices[0].registrationId,
            };

            const builder = new SessionBuilder(store, address);
            await builder.processPreKey(deviceObject);
        }
        const pushMessages = (await loadPushMessages()) as unknown as PushMessagesTyped;
        const PushMessageContent = pushMessages.PushMessageContent;
        const message = PushMessageContent.create({
            flags: data.endSession ? PushMessageFlags.END_SESSION : undefined,
            body: data.endSession ? undefined : data.smsText,
        });

        const buffer = PushMessageContent.encode(message).finish();
        const paddedBuffer = pad(buffer);
        const sessionCipher = new SessionCipher(store, address);

        const res = await sessionCipher.encrypt(paddedBuffer).then(async (msg) => {
            const expectedCiphertext = data.expectedCiphertext as Uint8Array<ArrayBufferLike>;

            if (msg.type == 1) {
                return util.isEqual(data.expectedCiphertext, msg.body);
            } else {
                if (expectedCiphertext[0] !== msg.body.charCodeAt(0)) {
                    throw new Error("Bad version byte");
                }
                const { PreKeyWhisperMessage } = await loadProtocolMessages();
                const decoded = PreKeyWhisperMessage.decode(expectedCiphertext.slice(1));
                const expected = PreKeyWhisperMessage.encode(decoded).finish();
                if (!util.isEqual(expected, msg.body.slice(1))) {
                    throw new Error("Result does not match expected ciphertext");
                }
                return true;
            }
        });
        if (data.endSession) {
            return sessionCipher.closeOpenSessionForDevice().then(function () {
                return res;
            });
        }
        return res;
    }

    function getDescription(step: TestVectorEntry): string {
        const direction = step[0];
        const data = step[1];
        if (direction === "receiveMessage") {
            const receiveData = data as ReceiveMessageData;
            if (receiveData.expectTerminateSession) {
                return "receive end session message";
            } else if (receiveData.type === 3) {
                return "receive prekey message " + receiveData.expectedSmsText;
            } else {
                return "receive message " + receiveData.expectedSmsText;
            }
        } else if (direction === "sendMessage") {
            const sendData = data as SendMessageData;
            if (sendData.endSession) {
                return "send end session message";
            } else if (sendData.ourIdentityKey) {
                return "send prekey message " + sendData.smsText;
            } else {
                return "send message " + sendData.smsText;
            }
        }
        return "";
    }

    TestVectors.forEach(function (test) {
        describe(test.name, function () {
            this.timeout(20000);

            const privKeyQueue: ArrayBuffer[] = [];
            const origCreateKeyPair = internalCrypto.createKeyPair;

            before(function () {
                internalCrypto.createKeyPair = async function (
                    privKey: ArrayBuffer
                ): Promise<KeyPair> {
                    if (privKey !== undefined) {
                        return origCreateKeyPair(privKey);
                    }

                    if (privKeyQueue.length == 0) {
                        throw new Error("Out of private keys");
                    } else {
                        const newPrivKey = privKeyQueue.shift();
                        if (!newPrivKey) throw new Error("Failed to fetch private key");

                        const keyPair = await internalCrypto.createKeyPair(newPrivKey);
                        if (util.toString(keyPair.privKey) != util.toString(newPrivKey))
                            throw new Error("Failed to rederive private key!");
                        else return keyPair;
                    }
                };
            });

            after(function () {
                internalCrypto.createKeyPair = origCreateKeyPair;
                if (privKeyQueue.length != 0) {
                    throw new Error("Leftover private keys");
                }
            });

            const store = new InMemoryStore();
            const address = OMEMOAddress.fromString("SNOWDEN.1");
            test.vectors.forEach(function (step) {
                it(getDescription(step), function (done) {
                    let doStep: typeof doReceiveStep | typeof doSendStep;
                    if (step[0] === "receiveMessage") {
                        doStep = doReceiveStep;
                    } else if (step[0] === "sendMessage") {
                        doStep = doSendStep;
                    } else {
                        throw new Error("Invalid test");
                    }

                    void                     void doStep(
                        store,
                        step[1] as unknown as SendMessageData & ReceiveMessageData,
                        privKeyQueue,
                        address
                    )
                        .then(assert)
                        .then(done, done);
                });
            });
        });
    });

    describe("encoding parameter", function () {
        const ALICE_ADDRESS = new OMEMOAddress("+14151111111", 1);
        const BOB_ADDRESS = new OMEMOAddress("+14152222222", 1);
        const originalMessage = util.toArrayBuffer(
            "L'homme est condamné à être libre"
        ) as ArrayBuffer;
        const aliceStore = new InMemoryStore();
        const bobStore = new InMemoryStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        let bobSessionCipher: SessionCipher, aliceSessionCipher: SessionCipher;

        before(async function () {
            await Promise.all([aliceStore, bobStore].map(generateIdentity));
            const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            await builder.processPreKey(preKeyBundle);
            aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);
            const ciphertext = await aliceSessionCipher.encrypt(originalMessage);
            return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, "binary");
        });

        function hexEncode(str: string) {
            return Array.from(str)
                .map(function (c: string) {
                    return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
                })
                .join("");
        }

        describe("decryptWhisperMessage", function () {
            it("accepts encoding='binary'", async function () {
                const ciphertext = await bobSessionCipher.encrypt(originalMessage);
                const plaintext = await aliceSessionCipher.decryptWhisperMessage(
                    ciphertext.body,
                    "binary"
                );
                assert.equal(util.toString(plaintext), util.toString(originalMessage));
            });

            it("accepts encoding='base64'", async function () {
                const ciphertext = await bobSessionCipher.encrypt(originalMessage);
                const plaintext = await aliceSessionCipher.decryptWhisperMessage(
                    btoa(ciphertext.body),
                    "base64"
                );
                assert.equal(util.toString(plaintext), util.toString(originalMessage));
            });

            it("accepts encoding='hex'", async function () {
                const ciphertext = await bobSessionCipher.encrypt(originalMessage);
                const plaintext = await aliceSessionCipher.decryptWhisperMessage(
                    hexEncode(ciphertext.body),
                    "hex"
                );
                assert.equal(util.toString(plaintext), util.toString(originalMessage));
            });
        });
    });

    describe("key changes", function () {
        const ALICE_ADDRESS = new OMEMOAddress("+14151111111", 1);
        const BOB_ADDRESS = new OMEMOAddress("+14152222222", 1);
        const originalMessage = util.toArrayBuffer(
            "L'homme est condamné à être libre"
        ) as ArrayBuffer;

        const aliceStore = new InMemoryStore();

        const bobStore = new InMemoryStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        const bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

        before(async function () {
            await Promise.all([aliceStore, bobStore].map(generateIdentity));
            const preKeyBundle = await generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
            const builder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            await builder.processPreKey(preKeyBundle);
            const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            const ciphertext = await aliceSessionCipher.encrypt(originalMessage);
            await bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, "binary");
        });

        describe("When bob's identity changes", function () {
            let messageFromBob: { body: string };

            before(async function () {
                messageFromBob = await bobSessionCipher.encrypt(originalMessage);

                await generateIdentity(bobStore);

                return aliceStore.saveIdentity(
                    BOB_ADDRESS.toString(),
                    (bobStore.get("identityKey") as KeyPair).pubKey
                );
            });

            it("alice cannot encrypt with the old session", async function () {
                const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
                try {
                    await aliceSessionCipher.encrypt(originalMessage);
                } catch (e) {
                    assert.strictEqual((e as Error).message, "Identity key changed");
                }
            });

            it("alice cannot decrypt from the old session", async function () {
                const aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
                try {
                    await aliceSessionCipher.decryptWhisperMessage(messageFromBob.body, "binary");
                } catch (e) {
                    assert.strictEqual((e as Error).message, "Identity key changed");
                }
            });
        });
    });
});

/* vim: ts=4:sw=4 */
/* global after, before, SignalProtocolStore, generateIdentity, generatePreKeyBundle, TestVectors, SessionCipher */

"use strict";
describe("SessionCipher", function () {
    const { assert } = chai;
    const { SignalProtocolAddress } = libomemo;

    describe("getRemoteRegistrationId", function () {
        const store = new SignalProtocolStore();
        const registrationId = 1337;
        const address = new libomemo.SignalProtocolAddress("foo", 1);
        const sessionCipher = new libomemo.SessionCipher(store, address.toString());

        describe("when an open record exists", function () {
            before(async () => {
                const record = new Internal.SessionRecord(registrationId);
                const session = {
                    registrationId: registrationId,
                    currentRatchet: {
                        rootKey: new ArrayBuffer(32),
                        lastRemoteEphemeralKey: new ArrayBuffer(32),
                        previousCounter: 0,
                    },
                    indexInfo: {
                        baseKey: new ArrayBuffer(32),
                        baseKeyType: Internal.BaseKeyType.OURS,
                        remoteIdentityKey: new ArrayBuffer(32),
                        closed: -1,
                    },
                    oldRatchetList: [],
                };
                record.updateSessionState(session);
                await store.storeSession(address.toString(), record.serialize());
            });

            it("returns a valid registrationId", async function () {
                const value = await sessionCipher.getRemoteRegistrationId();
                assert.strictEqual(value, registrationId);
            });
        });

        describe("when a record does not exist", function () {
            it("returns undefined", async function () {
                const sessionCipher = new libomemo.SessionCipher(store, "bar.1");
                const value = await sessionCipher.getRemoteRegistrationId();
                assert.isUndefined(value);
            });
        });
    });

    describe("hasOpenSession", function () {
        const store = new SignalProtocolStore();
        const address = new libomemo.SignalProtocolAddress("foo", 1);
        const sessionCipher = new libomemo.SessionCipher(store, address.toString());

        describe("open session exists", function () {
            before(async function () {
                const record = new Internal.SessionRecord();
                const session = {
                    registrationId: 1337,
                    currentRatchet: {
                        rootKey: new ArrayBuffer(32),
                        lastRemoteEphemeralKey: new ArrayBuffer(32),
                        previousCounter: 0,
                    },
                    indexInfo: {
                        baseKey: new ArrayBuffer(32),
                        baseKeyType: Internal.BaseKeyType.OURS,
                        remoteIdentityKey: new ArrayBuffer(32),
                        closed: -1,
                    },
                    oldRatchetList: [],
                };
                record.updateSessionState(session);
                await store.storeSession(address.toString(), record.serialize());
            });

            it("returns true", async function () {
                const value = await sessionCipher.hasOpenSession(address.toString());
                assert.isTrue(value);
            });
        });

        describe("no open session exists", function () {
            before(function (done) {
                const record = new Internal.SessionRecord();
                store.storeSession(address.toString(), record.serialize()).then(done);
            });

            it("returns false", async function () {
                const value = await sessionCipher.hasOpenSession(address.toString());
                assert.isFalse(value);
            });
        });
        describe("when there is no session", function () {
            it("returns false", async function () {
                const value = await sessionCipher.hasOpenSession("bar");
                assert.isFalse(value);
            });
        });
    });

    async function setupReceiveStep(store, data, privKeyQueue) {
        if (data.newEphemeralKey !== undefined) {
            privKeyQueue.push(data.newEphemeralKey);
        }

        if (data.ourIdentityKey === undefined) {
            return Promise.resolve();
        }

        const keyPair = await Internal.crypto.createKeyPair(data.ourIdentityKey);
        store.put("identityKey", keyPair);

        const signedKeyPair = await Internal.crypto.createKeyPair(data.ourSignedPreKey);
        store.storeSignedPreKey(data.signedPreKeyId, signedKeyPair);

        if (data.ourPreKey !== undefined) {
            const keyPair = await Internal.crypto.createKeyPair(data.ourPreKey);
            store.storePreKey(data.preKeyId, keyPair);
        }
    }

    function getPaddedMessageLength(messageLength) {
        const messageLengthWithTerminator = messageLength + 1;
        let messagePartCount = Math.floor(messageLengthWithTerminator / 160);

        if (messageLengthWithTerminator % 160 !== 0) {
            messagePartCount++;
        }

        return messagePartCount * 160;
    }

    function pad(plaintext) {
        const paddedPlaintext = new Uint8Array(
            getPaddedMessageLength(plaintext.byteLength + 1) - 1
        );
        paddedPlaintext.set(new Uint8Array(plaintext));
        paddedPlaintext[plaintext.byteLength] = 0x80;

        return paddedPlaintext.buffer;
    }

    function unpad(paddedPlaintext) {
        paddedPlaintext = new Uint8Array(paddedPlaintext);
        let plaintext;
        for (let i = paddedPlaintext.length - 1; i >= 0; i--) {
            if (paddedPlaintext[i] == 0x80) {
                plaintext = paddedPlaintext.subarray(0, i);
                break;
            } else if (paddedPlaintext[i] !== 0x00) {
                throw new Error("Invalid padding");
            }
        }
        return plaintext;
    }

    function doReceiveStep(store, data, privKeyQueue, address) {
        return setupReceiveStep(store, data, privKeyQueue)
            .then(async () => {
                const sessionCipher = new libomemo.SessionCipher(store, address);
                const pushMessages = await Internal.protobuf.loadPushMessages();
                if (data.type == pushMessages.IncomingPushMessageSignal.Type.CIPHERTEXT) {
                    return sessionCipher.decryptWhisperMessage(data.message).then(unpad);
                } else if (data.type == pushMessages.IncomingPushMessageSignal.Type.PREKEY_BUNDLE) {
                    return sessionCipher.decryptPreKeyWhisperMessage(data.message).then(unpad);
                } else {
                    throw new Error("Unknown data type in test vector");
                }
            })
            .then(async (plaintext) => {
                // Check result
                const pushMessages = await Internal.protobuf.loadPushMessages();
                const content = pushMessages.PushMessageContent.decode(new Uint8Array(plaintext));
                if (data.expectTerminateSession) {
                    if (content.flags == pushMessages.PushMessageContent.Flags.END_SESSION) {
                        return true;
                    } else {
                        return false;
                    }
                }
                return content.body == data.expectedSmsText;
            })
            .catch(function checkException(e) {
                if (data.expectException) {
                    return true;
                }
                throw e;
            });
    }

    async function setupSendStep(store, data, privKeyQueue) {
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
            const keyPair = await Internal.crypto.createKeyPair(data.ourIdentityKey);
            store.put("identityKey", keyPair);
        }
        return Promise.resolve();
    }

    function doSendStep(store, data, privKeyQueue, address) {
        return setupSendStep(store, data, privKeyQueue)
            .then(function () {
                if (data.getKeys !== undefined) {
                    const deviceObject = {
                        encodedNumber: address.toString(),
                        identityKey: data.getKeys.identityKey,
                        preKey: data.getKeys.devices[0].preKey,
                        signedPreKey: data.getKeys.devices[0].signedPreKey,
                        registrationId: data.getKeys.devices[0].registrationId,
                    };

                    const builder = new libomemo.SessionBuilder(store, address);

                    return builder.processPreKey(deviceObject);
                }
            })
            .then(async () => {
                const { PushMessageContent } = await Internal.protobuf.loadPushMessages();
                const message = PushMessageContent.create({
                    flags: data.endSession ? PushMessageContent.Flags.END_SESSION : undefined,
                    body: data.endSession ? undefined : data.smsText,
                });

                const buffer = PushMessageContent.encode(message).finish();
                const paddedBuffer = pad(buffer);
                const sessionCipher = new SessionCipher(store, address);

                return sessionCipher
                    .encrypt(paddedBuffer)
                    .then(async (msg) => {
                        //XXX: This should be all we do: isEqual(data.expectedCiphertext, encryptedMsg, false);
                        if (msg.type == 1) {
                            return util.isEqual(data.expectedCiphertext, msg.body);
                        } else {
                            if (data.expectedCiphertext[0] !== msg.body.charCodeAt(0)) {
                                throw new Error("Bad version byte");
                            }
                            const { PreKeyWhisperMessage } =
                                await Internal.protobuf.loadProtocolMessages();
                            const decoded = PreKeyWhisperMessage.decode(
                                data.expectedCiphertext.slice(1)
                            );
                            const expected = PreKeyWhisperMessage.encode(decoded).finish();
                            if (!util.isEqual(expected, msg.body.slice(1))) {
                                throw new Error("Result does not match expected ciphertext");
                            }
                            return true;
                        }
                    })
                    .then(function (res) {
                        if (data.endSession) {
                            return sessionCipher.closeOpenSessionForDevice().then(function () {
                                return res;
                            });
                        }
                        return res;
                    });
            });
    }

    function getDescription(step) {
        const direction = step[0];
        const data = step[1];
        if (direction === "receiveMessage") {
            if (data.expectTerminateSession) {
                return "receive end session message";
            } else if (data.type === 3) {
                return "receive prekey message " + data.expectedSmsText;
            } else {
                return "receive message " + data.expectedSmsText;
            }
        } else if (direction === "sendMessage") {
            if (data.endSession) {
                return "send end session message";
            } else if (data.ourIdentityKey) {
                return "send prekey message " + data.smsText;
            } else {
                return "send message " + data.smsText;
            }
        }
    }

    TestVectors.forEach(function (test) {
        describe(test.name, function () {
            this.timeout(20000);

            const privKeyQueue = [];
            const origCreateKeyPair = Internal.crypto.createKeyPair;

            before(function () {
                // Shim createKeyPair to return predetermined keys from
                // privKeyQueue instead of random keys.
                Internal.crypto.createKeyPair = function (privKey) {
                    if (privKey !== undefined) {
                        return origCreateKeyPair(privKey);
                    }
                    if (privKeyQueue.length == 0) {
                        throw new Error("Out of private keys");
                    } else {
                        const newPrivKey = privKeyQueue.shift();
                        return Internal.crypto.createKeyPair(newPrivKey).then(function (keyPair) {
                            if (util.toString(keyPair.privKey) != util.toString(newPrivKey))
                                throw new Error("Failed to rederive private key!");
                            else return keyPair;
                        });
                    }
                };
            });

            after(function () {
                Internal.crypto.createKeyPair = origCreateKeyPair;
                if (privKeyQueue.length != 0) {
                    throw new Error("Leftover private keys");
                }
            });

            const store = new SignalProtocolStore();
            const address = libomemo.SignalProtocolAddress.fromString("SNOWDEN.1");
            test.vectors.forEach(function (step) {
                it(getDescription(step), function (done) {
                    let doStep;
                    if (step[0] === "receiveMessage") {
                        doStep = doReceiveStep;
                    } else if (step[0] === "sendMessage") {
                        doStep = doSendStep;
                    } else {
                        throw new Error("Invalid test");
                    }

                    doStep(store, step[1], privKeyQueue, address).then(assert).then(done, done);
                });
            });
        });
    });

    describe("encoding parameter", function () {
        const ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
        const BOB_ADDRESS = new SignalProtocolAddress("+14152222222", 1);
        const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre");
        const aliceStore = new SignalProtocolStore();
        const bobStore = new SignalProtocolStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        let bobSessionCipher, aliceSessionCipher;

        before(function (done) {
            Promise.all([aliceStore, bobStore].map(generateIdentity))
                .then(function () {
                    return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
                })
                .then(function (preKeyBundle) {
                    const builder = new libomemo.SessionBuilder(aliceStore, BOB_ADDRESS);
                    return builder.processPreKey(preKeyBundle);
                })
                .then(function () {
                    aliceSessionCipher = new libomemo.SessionCipher(aliceStore, BOB_ADDRESS);
                    bobSessionCipher = new libomemo.SessionCipher(bobStore, ALICE_ADDRESS);
                    return aliceSessionCipher.encrypt(originalMessage);
                })
                .then(function (ciphertext) {
                    return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, "binary");
                })
                .then(function () {
                    done();
                })
                .catch(done);
        });

        function hexEncode(str) {
            return Array.from(str)
                .map(function (c) {
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
        const ALICE_ADDRESS = new SignalProtocolAddress("+14151111111", 1);
        const BOB_ADDRESS = new SignalProtocolAddress("+14152222222", 1);
        const originalMessage = util.toArrayBuffer("L'homme est condamné à être libre");

        const aliceStore = new SignalProtocolStore();

        const bobStore = new SignalProtocolStore();
        const bobPreKeyId = 1337;
        const bobSignedKeyId = 1;

        const bobSessionCipher = new libomemo.SessionCipher(bobStore, ALICE_ADDRESS);

        before(function (done) {
            Promise.all([aliceStore, bobStore].map(generateIdentity))
                .then(function () {
                    return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
                })
                .then(function (preKeyBundle) {
                    const builder = new libomemo.SessionBuilder(aliceStore, BOB_ADDRESS);
                    return builder
                        .processPreKey(preKeyBundle)
                        .then(function () {
                            const aliceSessionCipher = new libomemo.SessionCipher(
                                aliceStore,
                                BOB_ADDRESS
                            );
                            return aliceSessionCipher.encrypt(originalMessage);
                        })
                        .then(function (ciphertext) {
                            return bobSessionCipher.decryptPreKeyWhisperMessage(
                                ciphertext.body,
                                "binary"
                            );
                        })
                        .then(function () {
                            done();
                        });
                })
                .catch(done);
        });

        describe("When bob's identity changes", function () {
            let messageFromBob;

            before(async function () {
                messageFromBob = await bobSessionCipher.encrypt(originalMessage);

                generateIdentity(bobStore);

                return aliceStore.saveIdentity(
                    BOB_ADDRESS.toString(),
                    bobStore.get("identityKey").pubKey
                );
            });

            it("alice cannot encrypt with the old session", function () {
                const aliceSessionCipher = new libomemo.SessionCipher(aliceStore, BOB_ADDRESS);
                return aliceSessionCipher.encrypt(originalMessage).catch(function (e) {
                    assert.strictEqual(e.message, "Identity key changed");
                });
            });

            it("alice cannot decrypt from the old session", function () {
                const aliceSessionCipher = new libomemo.SessionCipher(aliceStore, BOB_ADDRESS);
                return aliceSessionCipher
                    .decryptWhisperMessage(messageFromBob.body, "binary")
                    .catch(function (e) {
                        assert.strictEqual(e.message, "Identity key changed");
                    });
            });
        });
    });
});

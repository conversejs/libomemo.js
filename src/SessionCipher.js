import { util } from "./helpers.js";
import { loadProtocolMessages } from "./protobufs.js";
import { SessionRecord, ChainType } from "./SessionRecord.js";
import { queueJobForNumber } from "./SessionLock.js";
import {
    internalCrypto,
    sign,
    verifyMAC,
    encrypt,
    decrypt,
    HKDF,
} from "./crypto.js";
import { SessionBuilder } from "./SessionBuilder.js";
import { SignalProtocolAddress } from "./SignalProtocolAddress.js";

export class SessionCipher {
    #remoteAddress;
    #storage;

    constructor(storage, remoteAddress) {
        this.#remoteAddress =
            typeof remoteAddress === "string"
                ? SignalProtocolAddress.fromString(remoteAddress)
                : remoteAddress;
        this.#storage = storage;
    }

    #getRecord(encodedNumber) {
        return this.#storage.loadSession(encodedNumber).then((serialized) => {
            if (serialized === undefined) {
                return undefined;
            }
            return SessionRecord.deserialize(serialized);
        });
    }

    #fillMessageKeys(chain, counter) {
        if (chain.chainKey.counter >= counter) {
            return Promise.resolve();
        }

        if (counter - chain.chainKey.counter > 2000) {
            throw new Error("Over 2000 messages into the future!");
        }

        if (chain.chainKey.key === undefined) {
            throw new Error("Got invalid request to extend chain after it was already closed");
        }

        const key = util.toArrayBuffer(chain.chainKey.key);
        const byteArray = new Uint8Array(1);
        byteArray[0] = 1;
        return sign(key, byteArray.buffer).then((mac) => {
            byteArray[0] = 2;
            return sign(key, byteArray.buffer).then((key) => {
                chain.messageKeys[chain.chainKey.counter + 1] = mac;
                chain.chainKey.key = key;
                chain.chainKey.counter += 1;
                return this.#fillMessageKeys(chain, counter);
            });
        });
    }

    #maybeStepRatchet(session, remoteKey, previousCounter) {
        if (session[util.toString(remoteKey)] !== undefined) {
            return Promise.resolve();
        }

        console.log("New remote ephemeral key");
        const ratchet = session.currentRatchet;

        return Promise.resolve()
            .then(() => {
                const previousRatchet = session[util.toString(ratchet.lastRemoteEphemeralKey)];
                if (previousRatchet !== undefined) {
                    return this.#fillMessageKeys(previousRatchet, previousCounter).then(() => {
                        delete previousRatchet.chainKey.key;
                        session.oldRatchetList[session.oldRatchetList.length] = {
                            added: Date.now(),
                            ephemeralKey: ratchet.lastRemoteEphemeralKey,
                        };
                    });
                }
            })
            .then(() => {
                return this.#calculateRatchet(session, remoteKey, false).then(() => {
                    const previousRatchet = util.toString(ratchet.ephemeralKeyPair.pubKey);
                    if (session[previousRatchet] !== undefined) {
                        ratchet.previousCounter = session[previousRatchet].chainKey.counter;
                        delete session[previousRatchet];
                    }

                    return internalCrypto.createKeyPair().then((keyPair) => {
                        ratchet.ephemeralKeyPair = keyPair;
                        return this.#calculateRatchet(session, remoteKey, true).then(() => {
                            ratchet.lastRemoteEphemeralKey = remoteKey;
                        });
                    });
                });
            });
    }

    #calculateRatchet(session, remoteKey, sending) {
        const ratchet = session.currentRatchet;

        return internalCrypto.ECDHE(remoteKey, util.toArrayBuffer(ratchet.ephemeralKeyPair.privKey)).then(
            (sharedSecret) => {
                return HKDF(
                    sharedSecret,
                    util.toArrayBuffer(ratchet.rootKey),
                    "WhisperRatchet"
                ).then((masterKey) => {
                    const ephemeralPublicKey = sending
                        ? ratchet.ephemeralKeyPair.pubKey
                        : remoteKey;
                    session[util.toString(ephemeralPublicKey)] = {
                        messageKeys: {},
                        chainKey: { counter: -1, key: masterKey[1] },
                        chainType: sending ? ChainType.SENDING : ChainType.RECEIVING,
                    };
                    ratchet.rootKey = masterKey[0];
                });
            }
        );
    }

    #doDecryptWhisperMessage(messageBytes, session) {
        if (!(messageBytes instanceof ArrayBuffer)) {
            throw new Error("Expected messageBytes to be an ArrayBuffer");
        }
        const version = new Uint8Array(messageBytes)[0];
        if ((version & 0xf) > 3 || version >> 4 < 3) {
            throw new Error("Incompatible version number on WhisperMessage");
        }
        const messageProto = new Uint8Array(messageBytes.slice(1, messageBytes.byteLength - 8));
        const mac = messageBytes.slice(messageBytes.byteLength - 8, messageBytes.byteLength);

        return loadProtocolMessages().then(({ WhisperMessage }) => {
            const message = WhisperMessage.decode(messageProto);
            const remoteEphemeralKey = message.ephemeralKey.slice().buffer;

            if (session === undefined) {
                return Promise.reject(
                    new Error(
                        `No session found to decrypt message from ${this.#remoteAddress.toString()}`
                    )
                );
            }
            if (session.indexInfo.closed !== -1) {
                console.log("decrypting message for closed session");
            }

            return this.#maybeStepRatchet(session, remoteEphemeralKey, message.previousCounter)
                .then(() => {
                    const chain = session[util.toString(message.ephemeralKey)];
                    if (chain.chainType === ChainType.SENDING) {
                        throw new Error("Tried to decrypt on a sending chain");
                    }

                    return this.#fillMessageKeys(chain, message.counter).then(() => {
                        const messageKey = chain.messageKeys[message.counter];
                        if (messageKey === undefined) {
                            const e = new Error(
                                "Message key not found. The counter was repeated or the key was not filled."
                            );
                            e.name = "MessageCounterError";
                            throw e;
                        }
                        delete chain.messageKeys[message.counter];
                        return HKDF(
                            util.toArrayBuffer(messageKey),
                            new ArrayBuffer(32),
                            "WhisperMessageKeys"
                        );
                    });
                })
                .then(async (keys) => {
                    const ourIdentityKey = await this.#storage.getIdentityKeyPair();

                    const macInput = new Uint8Array(messageProto.byteLength + 33 * 2 + 1);
                    macInput.set(
                        new Uint8Array(util.toArrayBuffer(session.indexInfo.remoteIdentityKey))
                    );
                    macInput.set(new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)), 33);
                    macInput[33 * 2] = (3 << 4) | 3;
                    macInput.set(new Uint8Array(messageProto), 33 * 2 + 1);
                    await verifyMAC(macInput.buffer, keys[1], mac, 8);
                    const plaintext = await decrypt(
                        keys[0],
                        message.ciphertext.slice().buffer,
                        keys[2].slice(0, 16)
                    );
                    delete session.pendingPreKey;
                    return plaintext;
                });
        });
    }

    #decryptWithSessionList(buffer, sessionList, errors) {
        if (sessionList.length === 0) {
            return Promise.reject(errors[0]);
        }

        const session = sessionList.pop();
        return this.#doDecryptWhisperMessage(buffer, session)
            .then((plaintext) => ({ plaintext, session }))
            .catch((e) => {
                if (e.name === "MessageCounterError") {
                    return Promise.reject(e);
                }
                errors.push(e);
                return this.#decryptWithSessionList(buffer, sessionList, errors);
            });
    }

    encrypt(buffer) {
        if (!(buffer instanceof ArrayBuffer)) {
            if (typeof buffer === "string") {
                buffer = new TextEncoder().encode(buffer).buffer;
            } else if (buffer instanceof Uint8Array) {
                buffer = buffer.buffer;
            } else {
                throw new Error("Expected buffer to be an ArrayBuffer, string, or Uint8Array");
            }
        }

        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();
            const { WhisperMessage } = await loadProtocolMessages();
            const msg = WhisperMessage.create();

            let ourIdentityKey, myRegistrationId, record, session, chain;

            const results = await Promise.all([
                this.#storage.getIdentityKeyPair(),
                this.#storage.getLocalRegistrationId(),
                this.#getRecord(address),
            ]);

            ourIdentityKey = results[0];
            myRegistrationId = results[1];
            record = results[2];
            if (!record) {
                throw new Error(`No record for ${address}`);
            }
            session = record.getOpenSession();
            if (!session) {
                throw new Error(`No session to encrypt message for ${address}`);
            }

            msg.ephemeralKey = new Uint8Array(
                util.toArrayBuffer(session.currentRatchet.ephemeralKeyPair.pubKey)
            );

            chain = session[util.toString(msg.ephemeralKey)];
            if (chain.chainType === ChainType.RECEIVING) {
                throw new Error("Tried to encrypt on a receiving chain");
            }

            await this.#fillMessageKeys(chain, chain.chainKey.counter + 1);

            const keys = await HKDF(
                util.toArrayBuffer(chain.messageKeys[chain.chainKey.counter]),
                new ArrayBuffer(32),
                "WhisperMessageKeys"
            );

            delete chain.messageKeys[chain.chainKey.counter];
            msg.counter = chain.chainKey.counter;
            msg.previousCounter = session.currentRatchet.previousCounter;

            const ciphertext = await encrypt(keys[0], buffer, keys[2].slice(0, 16));
            msg.ciphertext = new Uint8Array(ciphertext);

            const encodedMsg = WhisperMessage.encode(msg).finish();
            const macInput = new Uint8Array(encodedMsg.byteLength + 33 * 2 + 1);
            macInput.set(new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)));
            macInput.set(
                new Uint8Array(util.toArrayBuffer(session.indexInfo.remoteIdentityKey)),
                33
            );
            macInput[33 * 2] = (3 << 4) | 3;
            macInput.set(encodedMsg, 33 * 2 + 1);

            const mac = await sign(keys[1], macInput.buffer);
            const result = new Uint8Array(encodedMsg.byteLength + 9);
            result[0] = (3 << 4) | 3;
            result.set(encodedMsg, 1);
            result.set(new Uint8Array(mac, 0, 8), encodedMsg.byteLength + 1);

            const trusted = await this.#storage.isTrustedIdentity(
                this.#remoteAddress.getName(),
                util.toArrayBuffer(session.indexInfo.remoteIdentityKey),
                this.#storage.Direction.SENDING
            );
            if (!trusted) {
                throw new Error("Identity key changed");
            }
            await this.#storage.saveIdentity(
                this.#remoteAddress.toString(),
                session.indexInfo.remoteIdentityKey
            );

            record.updateSessionState(session);
            await this.#storage.storeSession(address, record.serialize());

            if (session.pendingPreKey !== undefined) {
                const { PreKeyWhisperMessage } = await loadProtocolMessages();
                const preKeyMsg = PreKeyWhisperMessage.create({
                    baseKey: new Uint8Array(
                        util.toArrayBuffer(session.pendingPreKey.baseKey)
                    ),
                    identityKey: new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)),
                    message: result,
                    preKeyId: session.pendingPreKey.preKeyId
                        ? session.pendingPreKey.preKeyId
                        : undefined,
                    registrationId: myRegistrationId,
                    signedPreKeyId: session.pendingPreKey.signedKeyId,
                });

                const encodedPreKeyMsg = PreKeyWhisperMessage.encode(preKeyMsg).finish();

                const preKeyResult = new Uint8Array(encodedPreKeyMsg.length + 1);
                preKeyResult[0] = (3 << 4) | 3;
                preKeyResult.set(encodedPreKeyMsg, 1);
                return {
                    type: 3,
                    body: util.toString(preKeyResult),
                    registrationId: session.registrationId,
                };
            } else {
                return {
                    type: 1,
                    body: util.toString(result),
                    registrationId: session.registrationId,
                };
            }
        });
    }

    decryptWhisperMessage(buffer, encoding) {
        buffer = util.normalizeBuffer(buffer, encoding).buffer;
        return queueJobForNumber(this.#remoteAddress.toString(), () => {
            const address = this.#remoteAddress.toString();
            return this.#getRecord(address).then((record) => {
                if (!record) {
                    throw new Error(`No record for device ${address}`);
                }
                const errors = [];
                return this.#decryptWithSessionList(buffer, record.getSessions(), errors).then(
                    (result) => {
                        return this.#getRecord(address).then((record) => {
                            if (
                                result.session.indexInfo.baseKey !==
                                record.getOpenSession().indexInfo.baseKey
                            ) {
                                record.archiveCurrentState();
                                record.promoteState(result.session);
                            }

                            return this.#storage
                                .isTrustedIdentity(
                                    this.#remoteAddress.getName(),
                                    util.toArrayBuffer(result.session.indexInfo.remoteIdentityKey),
                                    this.#storage.Direction.RECEIVING
                                )
                                .then((trusted) => {
                                    if (!trusted) {
                                        throw new Error("Identity key changed");
                                    }
                                })
                                .then(() => {
                                    return this.#storage.saveIdentity(
                                        this.#remoteAddress.toString(),
                                        result.session.indexInfo.remoteIdentityKey
                                    );
                                })
                                .then(() => {
                                    record.updateSessionState(result.session);
                                    return this.#storage
                                        .storeSession(address, record.serialize())
                                        .then(() => result.plaintext);
                                });
                        });
                    }
                );
            });
        });
    }

    decryptPreKeyWhisperMessage(buffer, encoding) {
        const bytes = util.normalizeBuffer(buffer, encoding);
        const version = bytes[0];
        if ((version & 0xf) > 3 || version >> 4 < 3) {
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }

        const arrayBuffer = bytes.buffer.slice(1);

        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();
            const { PreKeyWhisperMessage } = await loadProtocolMessages();
            const preKeyProto = PreKeyWhisperMessage.decode(new Uint8Array(arrayBuffer));

            let record = await this.#getRecord(address);
            if (!record) {
                if (preKeyProto.registrationId === undefined) {
                    throw new Error("No registrationId");
                }
                record = new SessionRecord();
            }
            const builder = new SessionBuilder(this.#storage, this.#remoteAddress);

            const preKeyId = await builder.processV3(record, preKeyProto);

            const session = record.getSessionByBaseKey(preKeyProto.baseKey);
            const plaintext = await this.#doDecryptWhisperMessage(
                preKeyProto.message.slice().buffer,
                session
            );
            record.updateSessionState(session);
            await this.#storage.storeSession(address, record.serialize());

            if (preKeyId !== undefined && preKeyId !== null) {
                this.#storage.removePreKey(preKeyId);
            }
            return plaintext;
        });
    }

    getRemoteRegistrationId() {
        return queueJobForNumber(this.#remoteAddress.toString(), () => {
            return this.#getRecord(this.#remoteAddress.toString()).then((record) => {
                if (record === undefined) {
                    return undefined;
                }
                const openSession = record.getOpenSession();
                if (openSession === undefined) {
                    return null;
                }
                return openSession?.registrationId ?? null;
            });
        });
    }

    hasOpenSession() {
        return queueJobForNumber(this.#remoteAddress.toString(), () => {
            return this.#getRecord(this.#remoteAddress.toString()).then((record) => {
                if (record === undefined) {
                    return false;
                }
                return record.haveOpenSession();
            });
        });
    }

    closeOpenSessionForDevice() {
        const address = this.#remoteAddress.toString();
        return queueJobForNumber(address, () => {
            return this.#getRecord(address).then((record) => {
                if (record === undefined || record.getOpenSession() === undefined) {
                    return;
                }
                record.archiveCurrentState();
                return this.#storage.storeSession(address, record.serialize());
            });
        });
    }

    deleteAllSessionsForDevice() {
        const address = this.#remoteAddress.toString();
        return queueJobForNumber(address, () => {
            return this.#getRecord(address).then((record) => {
                if (record === undefined) {
                    return;
                }
                record.deleteAllSessions();
                return this.#storage.storeSession(address, record.serialize());
            });
        });
    }
}



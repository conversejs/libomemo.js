/* global SessionBuilder */

class SessionCipher {

    constructor (storage, remoteAddress) {
        this.remoteAddress = remoteAddress;
        this.storage = storage;
    }

    getRecord (encodedNumber) {
        return this.storage.loadSession(encodedNumber).then((serialized) => {
          if (serialized === undefined) {
              return undefined;
          }
          return Internal.SessionRecord.deserialize(serialized);
      });
    }

    /**
     * Returns a Promise that resolves to a ciphertext object
     */
    encrypt (buffer) {
        if (!(buffer instanceof ArrayBuffer)) {
            if (typeof buffer === 'string') {
                buffer = new TextEncoder().encode(buffer).buffer;
            } else if (buffer instanceof Uint8Array) {
                buffer = buffer.buffer;
            } else {
                throw new Error("Expected buffer to be an ArrayBuffer, string, or Uint8Array");
            }
        }

        return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), async () => {
            const address = this.remoteAddress.toString();
            const { WhisperMessage }= await Internal.protobuf.loadProtocolMessages();
            const msg = WhisperMessage.create();

            let ourIdentityKey, myRegistrationId, record, session, chain;

            return Promise.all([
                this.storage.getIdentityKeyPair(),
                this.storage.getLocalRegistrationId(),
                this.getRecord(address)
            ]).then((results) => {
                ourIdentityKey   = results[0];
                myRegistrationId = results[1];
                record           = results[2];
                if (!record) {
                    throw new Error("No record for " + address);
                }
                session = record.getOpenSession();
                if (!session) {
                    throw new Error("No session to encrypt message for " + address);
                }

                msg.ephemeralKey = new Uint8Array(util.toArrayBuffer(
                    session.currentRatchet.ephemeralKeyPair.pubKey
                ));

                chain = session[util.toString(msg.ephemeralKey)];
                if (chain.chainType === Internal.ChainType.RECEIVING) {
                    throw new Error("Tried to encrypt on a receiving chain");
                }

                return this.fillMessageKeys(chain, chain.chainKey.counter + 1);
            }).then(() => {
                return Internal.HKDF(
                    util.toArrayBuffer(chain.messageKeys[chain.chainKey.counter]),
                    new ArrayBuffer(32),
                    "WhisperMessageKeys"
                );
            }).then((keys) => {
                delete chain.messageKeys[chain.chainKey.counter];
                msg.counter = chain.chainKey.counter;
                msg.previousCounter = session.currentRatchet.previousCounter;

                return Internal.crypto.encrypt(
                    keys[0], buffer, keys[2].slice(0, 16)
                ).then((ciphertext) => {
                    msg.ciphertext = new Uint8Array(ciphertext);

                    const encodedMsg = WhisperMessage.encode(msg).finish();
                    const macInput = new Uint8Array(encodedMsg.byteLength + 33*2 + 1);
                    macInput.set(new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)));
                    macInput.set(new Uint8Array(util.toArrayBuffer(session.indexInfo.remoteIdentityKey)), 33);
                    macInput[33*2] = (3 << 4) | 3;
                    macInput.set(encodedMsg, 33*2 + 1);

                    return Internal.crypto.sign(keys[1], macInput.buffer).then((mac) => {
                        const result = new Uint8Array(encodedMsg.byteLength + 9);
                        result[0] = (3 << 4) | 3;
                        result.set(encodedMsg, 1);
                        result.set(new Uint8Array(mac, 0, 8), encodedMsg.byteLength + 1);

                        return this.storage.isTrustedIdentity(
                            this.remoteAddress.getName(),
                            util.toArrayBuffer(session.indexInfo.remoteIdentityKey),
                            this.storage.Direction.SENDING
                        ).then((trusted) => {
                            if (!trusted) {
                                throw new Error('Identity key changed');
                            }
                            this.storage.saveIdentity(this.remoteAddress.toString(), session.indexInfo.remoteIdentityKey)
                        }).then(() => {
                            record.updateSessionState(session);
                            return this.storage.storeSession(address, record.serialize()).then(() => result)
                        });
                    });
                });
            }).then(async (message) => {
                if (session.pendingPreKey !== undefined) {
                    const { PreKeyWhisperMessage } = await Internal.protobuf.loadProtocolMessages();
                    const preKeyMsg = PreKeyWhisperMessage.create({
                        baseKey: new Uint8Array(util.toArrayBuffer(session.pendingPreKey.baseKey)),
                        identityKey: new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)),
                        message,
                        preKeyId: session.pendingPreKey.preKeyId ? session.pendingPreKey.preKeyId : undefined,
                        registrationId: myRegistrationId,
                        signedPreKeyId: session.pendingPreKey.signedKeyId,
                    });

                    const encodedPreKeyMsg = PreKeyWhisperMessage.encode(preKeyMsg).finish();

                    const result = new Uint8Array(encodedPreKeyMsg.length + 1);
                    result[0] = (3 << 4) | 3;
                    result.set(encodedPreKeyMsg, 1);
                    return {
                        type           : 3,
                        body           : util.toString(result),
                        registrationId : session.registrationId
                    };

                } else {
                    return {
                        type           : 1,
                        body           : util.toString(message),
                        registrationId : session.registrationId
                    };
                }
            });
        });
    }

    /**
     * Iterate recursively through the list, attempting to decrypt
     * using each one at a time. Stop and return the result if we get
     * a valid result
     */
    decryptWithSessionList (buffer, sessionList, errors) {
        if (sessionList.length === 0) {
            return Promise.reject(errors[0]);
        }

        const session = sessionList.pop();
        return this.doDecryptWhisperMessage(buffer, session)
            .then((plaintext) => ({ plaintext, session }))
            .catch((e) => {
                if (e.name === 'MessageCounterError') {
                    return Promise.reject(e);
                }
                errors.push(e);
                return this.decryptWithSessionList(buffer, sessionList, errors);
            });
    }

    /**
     * returns a Promise that resolves to decrypted plaintext array buffer
     */
    decryptWhisperMessage (buffer, encoding) {
        buffer = dcodeIO.ByteBuffer.wrap(buffer, encoding).toArrayBuffer();
        return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), () => {
            const address = this.remoteAddress.toString();
            return this.getRecord(address).then((record) => {
                if (!record) {
                    throw new Error("No record for device " + address);
                }
                const errors = [];
                return this.decryptWithSessionList(buffer, record.getSessions(), errors).then((result) => {
                    return this.getRecord(address).then((record) => {
                        if (result.session.indexInfo.baseKey !== record.getOpenSession().indexInfo.baseKey) {
                        record.archiveCurrentState();
                        record.promoteState(result.session);
                        }

                        return this.storage.isTrustedIdentity(
                            this.remoteAddress.getName(), util.toArrayBuffer(result.session.indexInfo.remoteIdentityKey), this.storage.Direction.RECEIVING
                        ).then((trusted) => {
                            if (!trusted) {
                                throw new Error('Identity key changed');
                            }
                        }).then(() => {
                            return this.storage.saveIdentity(this.remoteAddress.toString(), result.session.indexInfo.remoteIdentityKey);
                        }).then(() => {
                            record.updateSessionState(result.session);
                            return this.storage.storeSession(address, record.serialize()).then(() => result.plaintext);
                        });
                    });
                });
            });
        });
    }

    /**
     * returns a Promise that inits a session if necessary and resolves
     * to a decrypted plaintext array buffer
     */
    decryptPreKeyWhisperMessage (buffer, encoding) {
        const bytebuffer = dcodeIO.ByteBuffer.wrap(buffer, encoding);
        const version = bytebuffer.readUint8();
        if ((version & 0xF) > 3 || (version >> 4) < 3) {  // min version > 3 or max version < 3
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }

        const arrayBuffer = bytebuffer.toArrayBuffer();

        return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), async () => {
            const address = this.remoteAddress.toString();
            const { PreKeyWhisperMessage }= await Internal.protobuf.loadProtocolMessages();
            const preKeyProto = PreKeyWhisperMessage.decode(new Uint8Array(arrayBuffer));

            let record = await this.getRecord(address);
            if (!record) {
                if (preKeyProto.registrationId === undefined) {
                    throw new Error("No registrationId");
                }
                record = new Internal.SessionRecord(
                    preKeyProto.registrationId
                );
            }
            const builder = new SessionBuilder(this.storage, this.remoteAddress);

            // isTrustedIdentity is called within processV3, no need to call it here
            const preKeyId = await builder.processV3(record, preKeyProto);

            const session = record.getSessionByBaseKey(preKeyProto.baseKey);
            const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message.slice().buffer, session);
            record.updateSessionState(session);
            await this.storage.storeSession(address, record.serialize());

            if (preKeyId !== undefined && preKeyId !== null) {
                this.storage.removePreKey(preKeyId);
            }
            return plaintext;
        });
    }

    async doDecryptWhisperMessage (messageBytes, session) {
        if (!(messageBytes instanceof ArrayBuffer)) {
            throw new Error("Expected messageBytes to be an ArrayBuffer");
        }
        const version = (new Uint8Array(messageBytes))[0];
        if ((version & 0xF) > 3 || (version >> 4) < 3) {  // min version > 3 or max version < 3
            throw new Error("Incompatible version number on WhisperMessage");
        }
        const messageProto = new Uint8Array(messageBytes.slice(1, messageBytes.byteLength- 8));
        const mac = messageBytes.slice(messageBytes.byteLength - 8, messageBytes.byteLength);

        const { WhisperMessage } = await Internal.protobuf.loadProtocolMessages();
        const message = WhisperMessage.decode(messageProto);
        const remoteEphemeralKey = message.ephemeralKey.slice().buffer;

        if (session === undefined) {
            return Promise.reject(new Error("No session found to decrypt message from " + this.remoteAddress.toString()));
        }
        if (session.indexInfo.closed != -1) {
            console.log('decrypting message for closed session');
        }

        return this.maybeStepRatchet(session, remoteEphemeralKey, message.previousCounter).then(() => {
            const chain = session[util.toString(message.ephemeralKey)];
            if (chain.chainType === Internal.ChainType.SENDING) {
                throw new Error("Tried to decrypt on a sending chain");
            }

            return this.fillMessageKeys(chain, message.counter).then(() => {
                const messageKey = chain.messageKeys[message.counter];
                if (messageKey === undefined) {
                    const e = new Error("Message key not found. The counter was repeated or the key was not filled.");
                    e.name = 'MessageCounterError';
                    throw e;
                }
                delete chain.messageKeys[message.counter];
                return Internal.HKDF(util.toArrayBuffer(messageKey), new ArrayBuffer(32), "WhisperMessageKeys");
            });
        }).then(async (keys) => {
            const ourIdentityKey = await this.storage.getIdentityKeyPair();

            const macInput = new Uint8Array(messageProto.byteLength + 33*2 + 1);
            macInput.set(new Uint8Array(util.toArrayBuffer(session.indexInfo.remoteIdentityKey)));
            macInput.set(new Uint8Array(util.toArrayBuffer(ourIdentityKey.pubKey)), 33);
            macInput[33*2] = (3 << 4) | 3;
            macInput.set(new Uint8Array(messageProto), 33*2 + 1);
            await Internal.verifyMAC(macInput.buffer, keys[1], mac, 8);
            const plaintext = await Internal.crypto.decrypt(keys[0], message.ciphertext.slice().buffer, keys[2].slice(0, 16));
            delete session.pendingPreKey;
            return plaintext;
        });
    }

    fillMessageKeys (chain, counter) {
        if (chain.chainKey.counter >= counter) {
            return Promise.resolve(); // Already calculated
        }

        if (counter - chain.chainKey.counter > 2000) {
            throw new Error('Over 2000 messages into the future!');
        }

        if (chain.chainKey.key === undefined) {
            throw new Error("Got invalid request to extend chain after it was already closed");
        }

        const key = util.toArrayBuffer(chain.chainKey.key);
        const byteArray = new Uint8Array(1);
        byteArray[0] = 1;
        return Internal.crypto.sign(key, byteArray.buffer).then((mac) => {
            byteArray[0] = 2;
            return Internal.crypto.sign(key, byteArray.buffer).then((key) => {
                chain.messageKeys[chain.chainKey.counter + 1] = mac;
                chain.chainKey.key = key;
                chain.chainKey.counter += 1;
                return this.fillMessageKeys(chain, counter);
            });
        });
    }

    maybeStepRatchet (session, remoteKey, previousCounter) {
        if (session[util.toString(remoteKey)] !== undefined) {
            return Promise.resolve();
        }

        console.log('New remote ephemeral key');
        const ratchet = session.currentRatchet;

        return Promise.resolve().then(() => {
            const previousRatchet = session[util.toString(ratchet.lastRemoteEphemeralKey)];
            if (previousRatchet !== undefined) {
                return this.fillMessageKeys(previousRatchet, previousCounter).then(() => {
                    delete previousRatchet.chainKey.key;
                    session.oldRatchetList[session.oldRatchetList.length] = {
                        added        : Date.now(),
                        ephemeralKey : ratchet.lastRemoteEphemeralKey
                    };
                });
            }
        }).then(() => {
            return this.calculateRatchet(session, remoteKey, false).then(() => {
                // Now swap the ephemeral key and calculate the new sending chain
                const previousRatchet = util.toString(ratchet.ephemeralKeyPair.pubKey);
                if (session[previousRatchet] !== undefined) {
                    ratchet.previousCounter = session[previousRatchet].chainKey.counter;
                    delete session[previousRatchet];
                }

                return Internal.crypto.createKeyPair().then((keyPair) => {
                    ratchet.ephemeralKeyPair = keyPair;
                    return this.calculateRatchet(session, remoteKey, true).then(() => {
                        ratchet.lastRemoteEphemeralKey = remoteKey;
                    });
                });
            });
        });
    }

    calculateRatchet (session, remoteKey, sending) {
        const ratchet = session.currentRatchet;

        return Internal.crypto.ECDHE(remoteKey, util.toArrayBuffer(ratchet.ephemeralKeyPair.privKey)).then((sharedSecret) => {
            return Internal.HKDF(sharedSecret, util.toArrayBuffer(ratchet.rootKey), "WhisperRatchet").then((masterKey) => {
                const ephemeralPublicKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
                session[util.toString(ephemeralPublicKey)] = {
                    messageKeys: {},
                    chainKey: { counter: -1, key: masterKey[1] },
                    chainType: sending ? Internal.ChainType.SENDING : Internal.ChainType.RECEIVING
                };
                ratchet.rootKey = masterKey[0];
            });
        });
    }

    getRemoteRegistrationId () {
        return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), () =>{
            return this.getRecord(this.remoteAddress.toString()).then((record) => {
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

    hasOpenSession () {
        return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), () => {
            return this.getRecord(this.remoteAddress.toString()).then((record) => {
                if (record === undefined) {
                    return false;
                }
                return record.haveOpenSession();
            });
        });
    }

    closeOpenSessionForDevice () {
        const address = this.remoteAddress.toString();
        return Internal.SessionLock.queueJobForNumber(address, () => {
            return this.getRecord(address).then((record) => {
                if (record === undefined || record.getOpenSession() === undefined) {
                    return;
                }
                record.archiveCurrentState();
                return this.storage.storeSession(address, record.serialize());
            });
        });
    }

    /**
     * Used in session reset scenarios, where we really need to delete
     */
    deleteAllSessionsForDevice () {
        const address = this.remoteAddress.toString();
        return Internal.SessionLock.queueJobForNumber(address, () => {
            return this.getRecord(address).then((record) => {
                if (record === undefined) {
                    return;
                }
                record.deleteAllSessions();
                return this.storage.storeSession(address, record.serialize());
            });
        });
    }
}

libsignal.SessionCipher = function (storage, remoteAddress) {
    const cipher = new SessionCipher(storage, remoteAddress);
    this.encrypt = (buffer) => cipher.encrypt(buffer);
    this.decryptPreKeyWhisperMessage = (buffer, encoding) => cipher.decryptPreKeyWhisperMessage(buffer, encoding);
    this.decryptWhisperMessage = (buffer, encoding) => cipher.decryptWhisperMessage(buffer, encoding);
    this.getRemoteRegistrationId = () => cipher.getRemoteRegistrationId();
    this.hasOpenSession = () => cipher.hasOpenSession();
    this.closeOpenSessionForDevice = () => cipher.closeOpenSessionForDevice();
    this.deleteAllSessionsForDevice = () => cipher.deleteAllSessionsForDevice();
};

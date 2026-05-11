import { util } from "./helpers.js";
import { loadProtocolMessages } from "./protobufs.js";
import { SessionRecord, ChainType } from "./SessionRecord.js";
import { queueJobForNumber } from "./SessionLock.js";
import { internalCrypto, sign, verifyMAC, encrypt, decrypt, HKDF } from "./crypto.js";
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

    async #getRecord(encodedNumber) {
        const serialized = await this.#storage.loadSession(encodedNumber);
        if (serialized === undefined) return;

        return SessionRecord.deserialize(serialized);
    }

    async #fillMessageKeys(chain, counter) {
        if (chain.chainKey.counter >= counter) {
            return Promise.resolve();
        }

        if (counter - chain.chainKey.counter > 2000) {
            throw new Error("Over 2000 messages into the future!");
        }

        if (chain.chainKey.key === undefined) {
            throw new Error("Got invalid request to extend chain after it was already closed");
        }

        let key = util.toArrayBuffer(chain.chainKey.key);
        const byteArray = new Uint8Array(1);
        byteArray[0] = 1;

        const mac = await sign(key, byteArray.buffer);
        byteArray[0] = 2;

        key = await sign(key, byteArray.buffer);
        chain.messageKeys[chain.chainKey.counter + 1] = mac;
        chain.chainKey.key = key;
        chain.chainKey.counter += 1;

        return this.#fillMessageKeys(chain, counter);
    }

    async #maybeStepRatchet(session, remoteKey, previousCounter) {
        if (session[util.toString(remoteKey)] !== undefined) {
            return;
        }
        console.log("New remote ephemeral key");

        const ratchet = session.currentRatchet;

        let previousRatchet = session[util.toString(ratchet.lastRemoteEphemeralKey)];
        if (previousRatchet !== undefined) {
            await this.#fillMessageKeys(previousRatchet, previousCounter);
            delete previousRatchet.chainKey.key;
            session.oldRatchetList[session.oldRatchetList.length] = {
                added: Date.now(),
                ephemeralKey: ratchet.lastRemoteEphemeralKey,
            };
        }

        await this.#calculateRatchet(session, remoteKey, false);

        previousRatchet = util.toString(ratchet.ephemeralKeyPair.pubKey);
        if (session[previousRatchet] !== undefined) {
            ratchet.previousCounter = session[previousRatchet].chainKey.counter;
            delete session[previousRatchet];
        }

        const keyPair = await internalCrypto.createKeyPair();
        ratchet.ephemeralKeyPair = keyPair;

        await this.#calculateRatchet(session, remoteKey, true);
        ratchet.lastRemoteEphemeralKey = remoteKey;
    }

    async #calculateRatchet(session, remoteKey, sending) {
        const ratchet = session.currentRatchet;
        const sharedSecret = await internalCrypto.ECDHE(
            remoteKey,
            util.toArrayBuffer(ratchet.ephemeralKeyPair.privKey)
        );
        const masterKey = await HKDF(
            sharedSecret,
            util.toArrayBuffer(ratchet.rootKey),
            "WhisperRatchet"
        );
        const ephemeralPublicKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
        session[util.toString(ephemeralPublicKey)] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING,
        };
        ratchet.rootKey = masterKey[0];
    }

    async #doDecryptWhisperMessage(messageBytes, session) {
        if (!(messageBytes instanceof ArrayBuffer)) {
            throw new Error("Expected messageBytes to be an ArrayBuffer");
        }
        const version = new Uint8Array(messageBytes)[0];
        if ((version & 0xf) > 3 || version >> 4 < 3) {
            throw new Error("Incompatible version number on WhisperMessage");
        }

        const messageProto = new Uint8Array(messageBytes.slice(1, messageBytes.byteLength - 8));
        const mac = messageBytes.slice(messageBytes.byteLength - 8, messageBytes.byteLength);

        const { WhisperMessage } = await loadProtocolMessages();
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

        await this.#maybeStepRatchet(session, remoteEphemeralKey, message.previousCounter);
        const chain = session[util.toString(message.ephemeralKey)];
        if (chain.chainType === ChainType.SENDING) {
            throw new Error("Tried to decrypt on a sending chain");
        }

        await this.#fillMessageKeys(chain, message.counter);

        const messageKey = chain.messageKeys[message.counter];
        if (messageKey === undefined) {
            const e = new Error(
                "Message key not found. The counter was repeated or the key was not filled."
            );
            e.name = "MessageCounterError";
            throw e;
        }
        delete chain.messageKeys[message.counter];

        const keys = await HKDF(
            util.toArrayBuffer(messageKey),
            new ArrayBuffer(32),
            "WhisperMessageKeys"
        );

        const ourIdentityKey = await this.#storage.getIdentityKeyPair();

        const macInput = new Uint8Array(messageProto.byteLength + 33 * 2 + 1);
        macInput.set(new Uint8Array(util.toArrayBuffer(session.indexInfo.remoteIdentityKey)));
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
    }

    async #decryptWithSessionList(buffer, sessionList, errors = []) {
        if (sessionList.length === 0) {
            return Promise.reject(errors[0]);
        }

        const session = sessionList.pop();
        try {
            return {
                plaintext: await this.#doDecryptWhisperMessage(buffer, session),
                session,
            };
        } catch (e) {
            if (e.name === "MessageCounterError") {
                throw e;
            }
            errors.push(e);
            return this.#decryptWithSessionList(buffer, sessionList, errors);
        }
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
                    baseKey: new Uint8Array(util.toArrayBuffer(session.pendingPreKey.baseKey)),
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

    async decryptWhisperMessage(buffer, encoding) {
        buffer = util.normalizeBuffer(buffer, encoding).buffer;
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();

            const record = await this.#getRecord(address);
            if (!record) throw new Error(`No record for device ${address}`);

            const { session, plaintext } = await this.#decryptWithSessionList(
                buffer,
                record.getSessions()
            );

            if (session.indexInfo.baseKey !== record.getOpenSession().indexInfo.baseKey) {
                record.archiveCurrentState();
                record.promoteState(session);
            }

            const trusted = await this.#storage.isTrustedIdentity(
                this.#remoteAddress.getName(),
                util.toArrayBuffer(session.indexInfo.remoteIdentityKey),
                this.#storage.Direction.RECEIVING
            );
            if (!trusted) throw new Error("Identity key changed");

            await this.#storage.saveIdentity(
                this.#remoteAddress.toString(),
                session.indexInfo.remoteIdentityKey
            );
            record.updateSessionState(session);

            await this.#storage.storeSession(address, record.serialize());

            return plaintext;
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
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const record = await this.#getRecord(this.#remoteAddress.toString());
            if (record === undefined) return;

            const openSession = record.getOpenSession();
            if (openSession === undefined) return null;

            return openSession?.registrationId ?? null;
        });
    }

    hasOpenSession() {
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const record = await this.#getRecord(this.#remoteAddress.toString());
            if (record === undefined) return false;

            return record.haveOpenSession();
        });
    }

    closeOpenSessionForDevice() {
        const address = this.#remoteAddress.toString();
        return queueJobForNumber(address, async () => {
            const record = await this.#getRecord(address);
            if (record === undefined || record.getOpenSession() === undefined) {
                return;
            }

            record.archiveCurrentState();
            return this.#storage.storeSession(address, record.serialize());
        });
    }

    deleteAllSessionsForDevice() {
        const address = this.#remoteAddress.toString();
        return queueJobForNumber(address, async () => {
            const record = await this.#getRecord(address);
            if (record === undefined) {
                return;
            }
            record.deleteAllSessions();
            return this.#storage.storeSession(address, record.serialize());
        });
    }
}

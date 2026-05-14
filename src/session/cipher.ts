import { util } from "../helpers";
import { loadProtocolMessages } from "../protobufs";
import { SessionRecord } from "./record";
import { queueJobForNumber } from "./lock";
import { internalCrypto, sign, verifyMAC, encrypt, decrypt, HKDF } from "../crypto";
import { SessionBuilder } from "./builder";
import { OMEMOAddress } from "./address";
import { ChainType } from "../types";
import { EncryptResult, SessionState, OMEMOStore, Direction, Chain } from "./types";

export class SessionCipher {
    #remoteAddress: OMEMOAddress;
    #store: OMEMOStore;

    constructor(store: OMEMOStore, remoteAddress: OMEMOAddress | string) {
        this.#remoteAddress =
            typeof remoteAddress === "string"
                ? OMEMOAddress.fromString(remoteAddress)
                : remoteAddress;
        this.#store = store;
    }

    async #getRecord(encodedNumber: string): Promise<SessionRecord | undefined> {
        const serialized = await this.#store.loadSession(encodedNumber);
        if (serialized === undefined) return undefined;

        return SessionRecord.deserialize(serialized);
    }

    async #fillMessageKeys(chain: Chain, counter: number): Promise<void> {
        if (chain.chainKey.counter >= counter) {
            return Promise.resolve();
        }

        if (counter - chain.chainKey.counter > 2000) {
            throw new Error("Over 2000 messages into the future!");
        }

        if (chain.chainKey.key === undefined) {
            throw new Error("Got invalid request to extend chain after it was already closed");
        }

        let key = chain.chainKey.key;
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

    async #maybeStepRatchet(
        session: SessionState,
        remoteKey: ArrayBuffer,
        previousCounter: number
    ): Promise<void> {
        const remoteKeyStr = util.toString(remoteKey) as keyof SessionState;
        if (session[remoteKeyStr] !== undefined) {
            return;
        }
        console.log("New remote ephemeral key");

        const ratchet = session.currentRatchet;

        const lastRemoteKeyStr = util.toString(
            ratchet.lastRemoteEphemeralKey
        ) as keyof SessionState;
        let previousRatchet = session[lastRemoteKeyStr];
        if (previousRatchet !== undefined) {
            await this.#fillMessageKeys(previousRatchet as Chain, previousCounter);
            delete (previousRatchet as { chainKey: { key?: ArrayBuffer } }).chainKey.key;
            session.oldRatchetList[session.oldRatchetList.length] = {
                added: Date.now(),
                ephemeralKey: ratchet.lastRemoteEphemeralKey,
            };
        }

        await this.#calculateRatchet(session, remoteKey, false);

        const ephemeralPubKeyStr = util.toString(
            ratchet.ephemeralKeyPair.pubKey
        ) as keyof SessionState;

        previousRatchet = session[ephemeralPubKeyStr];
        if (previousRatchet !== undefined) {
            ratchet.previousCounter = (
                previousRatchet as { chainKey: { counter: number } }
            ).chainKey.counter;
            delete session[ephemeralPubKeyStr];
        }

        const keyPair = await internalCrypto.createKeyPair();
        ratchet.ephemeralKeyPair = keyPair;

        await this.#calculateRatchet(session, remoteKey, true);
        ratchet.lastRemoteEphemeralKey = remoteKey;
    }

    async #calculateRatchet(
        session: SessionState,
        remoteKey: ArrayBuffer,
        sending: boolean
    ): Promise<void> {
        const ratchet = session.currentRatchet;
        const sharedSecret = await internalCrypto.ECDHE(
            remoteKey,
            ratchet.ephemeralKeyPair.privKey
        );
        const masterKey = await HKDF(sharedSecret, ratchet.rootKey, "WhisperRatchet");
        const ephemeralPublicKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
        const ephemeralKeyStr = util.toString(ephemeralPublicKey) as keyof SessionState;
        session[ephemeralKeyStr] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING,
        };
        ratchet.rootKey = masterKey[0];
    }

    async #doDecryptWhisperMessage(
        messageBytes: ArrayBuffer,
        session: SessionState | undefined
    ): Promise<ArrayBuffer> {
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
        const message = WhisperMessage.decode(messageProto) as any;
        const remoteEphemeralKey = message.ephemeralKey.slice().buffer as ArrayBuffer;

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
        const chain = session[util.toString(message.ephemeralKey) as keyof SessionState] as Chain;
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

        const keys = await HKDF(messageKey, new ArrayBuffer(32), "WhisperMessageKeys");

        const ourIdentityKey = await this.#store.getIdentityKeyPair();
        if (!ourIdentityKey) throw new Error("No identity keypair to verify MAC");

        const macInput = new Uint8Array(messageProto.byteLength + 33 * 2 + 1);
        macInput.set(new Uint8Array(session.indexInfo.remoteIdentityKey));
        macInput.set(new Uint8Array(ourIdentityKey.pubKey), 33);
        macInput[33 * 2] = (3 << 4) | 3;
        macInput.set(new Uint8Array(messageProto), 33 * 2 + 1);
        await verifyMAC(macInput.buffer, keys[1], mac, 8);

        const plaintext = await decrypt(
            keys[0],
            message.ciphertext.slice().buffer as ArrayBuffer,
            keys[2].slice(0, 16)
        );
        delete session.pendingPreKey;
        return plaintext;
    }

    async #decryptWithSessionList(
        buffer: ArrayBuffer,
        sessionList: SessionState[],
        errors: unknown[] = []
    ): Promise<{ plaintext: ArrayBuffer; session: SessionState }> {
        if (sessionList.length === 0) {
            return Promise.reject(errors[0]);
        }

        const session = sessionList.pop()!;
        try {
            return {
                plaintext: await this.#doDecryptWhisperMessage(buffer, session),
                session,
            };
        } catch (e: unknown) {
            if ((e as Error).name === "MessageCounterError") {
                throw e;
            }
            errors.push(e);
            return this.#decryptWithSessionList(buffer, sessionList, errors);
        }
    }

    encrypt(buffer: ArrayBuffer | string | Uint8Array): Promise<EncryptResult> {
        let buf: ArrayBuffer;
        if (!(buffer instanceof ArrayBuffer)) {
            if (typeof buffer === "string") {
                buf = new TextEncoder().encode(buffer).buffer;
            } else if (buffer instanceof Uint8Array) {
                buf = buffer.buffer as ArrayBuffer;
            } else {
                throw new Error("Expected buffer to be an ArrayBuffer, string, or Uint8Array");
            }
        } else {
            buf = buffer;
        }

        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();
            const { WhisperMessage } = await loadProtocolMessages();
            const msg = WhisperMessage.create() as any;

            let session: SessionState | undefined;
            let chain: Chain;

            const [ourIdentityKey, myRegistrationId, record] = await Promise.all([
                this.#store.getIdentityKeyPair(),
                this.#store.getLocalRegistrationId(),
                this.#getRecord(address),
            ]);

            if (!ourIdentityKey) throw new Error("Can't encrypt: no identity key");

            if (!record) throw new Error(`Can't encrypt: no record for ${address}`);

            session = record.getOpenSession();
            if (!session) {
                throw new Error(`No session to encrypt message for ${address}`);
            }

            msg.ephemeralKey = new Uint8Array(session.currentRatchet.ephemeralKeyPair.pubKey);

            const ephemeralKeyStr = util.toString(msg.ephemeralKey) as keyof SessionState;

            chain = session[ephemeralKeyStr] as typeof chain;
            if (chain.chainType === ChainType.RECEIVING) {
                throw new Error("Tried to encrypt on a receiving chain");
            }

            await this.#fillMessageKeys(chain, chain.chainKey.counter + 1);

            const keys = await HKDF(
                chain.messageKeys[chain.chainKey.counter],
                new ArrayBuffer(32),
                "WhisperMessageKeys"
            );

            delete chain.messageKeys[chain.chainKey.counter];
            msg.counter = chain.chainKey.counter;
            msg.previousCounter = session.currentRatchet.previousCounter;

            const ciphertext = await encrypt(keys[0], buf, keys[2].slice(0, 16));
            msg.ciphertext = new Uint8Array(ciphertext);

            const encodedMsg = WhisperMessage.encode(msg).finish();
            const macInput = new Uint8Array(encodedMsg.byteLength + 33 * 2 + 1);
            macInput.set(new Uint8Array(ourIdentityKey.pubKey));
            macInput.set(new Uint8Array(session.indexInfo.remoteIdentityKey), 33);
            macInput[33 * 2] = (3 << 4) | 3;
            macInput.set(encodedMsg, 33 * 2 + 1);

            const mac = await sign(keys[1], macInput.buffer);
            const result = new Uint8Array(encodedMsg.byteLength + 9);
            result[0] = (3 << 4) | 3;
            result.set(encodedMsg, 1);
            result.set(new Uint8Array(mac, 0, 8), encodedMsg.byteLength + 1);

            const trusted = await this.#store.isTrustedIdentity(
                this.#remoteAddress.getName(),
                session.indexInfo.remoteIdentityKey,
                Direction.SENDING
            );
            if (!trusted) {
                throw new Error("Identity key changed");
            }
            await this.#store.saveIdentity(
                this.#remoteAddress.toString(),
                session.indexInfo.remoteIdentityKey
            );

            record.updateSessionState(session);
            await this.#store.storeSession(address, record.serialize());

            if (session.pendingPreKey !== undefined) {
                const { PreKeyWhisperMessage } = await loadProtocolMessages();
                const preKeyMsg = PreKeyWhisperMessage.create({
                    baseKey: new Uint8Array(session.pendingPreKey.baseKey),
                    identityKey: new Uint8Array(ourIdentityKey.pubKey),
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

    async decryptWhisperMessage(
        buffer: string | ArrayBuffer | Uint8Array,
        encoding: string
    ): Promise<ArrayBuffer> {
        buffer = util.normalizeBuffer(buffer, encoding).buffer as ArrayBuffer;
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();

            const record = await this.#getRecord(address);
            if (!record) throw new Error(`No record for device ${address}`);

            const { session, plaintext } = await this.#decryptWithSessionList(
                buffer,
                record.getSessions()
            );

            if (session.indexInfo.baseKey !== record.getOpenSession()!.indexInfo.baseKey) {
                record.archiveCurrentState();
                record.promoteState(session);
            }

            const trusted = await this.#store.isTrustedIdentity(
                this.#remoteAddress.getName(),
                session.indexInfo.remoteIdentityKey,
                Direction.RECEIVING
            );
            if (!trusted) throw new Error("Identity key changed");

            await this.#store.saveIdentity(
                this.#remoteAddress.toString(),
                session.indexInfo.remoteIdentityKey
            );
            record.updateSessionState(session);

            await this.#store.storeSession(address, record.serialize());

            return plaintext;
        });
    }

    decryptPreKeyWhisperMessage(
        buffer: string | ArrayBuffer | Uint8Array,
        encoding: string
    ): Promise<ArrayBuffer> {
        const bytes = util.normalizeBuffer(buffer, encoding);
        const version = bytes[0];
        if ((version & 0xf) > 3 || version >> 4 < 3) {
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }

        const arrayBuffer = bytes.buffer.slice(1) as ArrayBuffer;

        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();
            const { PreKeyWhisperMessage } = await loadProtocolMessages();
            const preKeyProto = PreKeyWhisperMessage.decode(new Uint8Array(arrayBuffer)) as any;

            let record = await this.#getRecord(address);
            if (!record) {
                if (preKeyProto.registrationId === undefined) {
                    throw new Error("No registrationId");
                }
                record = new SessionRecord();
            }
            const builder = new SessionBuilder(this.#store, this.#remoteAddress);

            const preKeyId = await builder.processV3(record, preKeyProto);

            const session = record.getSessionByBaseKey(preKeyProto.baseKey);
            const plaintext = await this.#doDecryptWhisperMessage(
                preKeyProto.message.slice().buffer as ArrayBuffer,
                session
            );
            record.updateSessionState(session!);
            await this.#store.storeSession(address, record.serialize());

            if (preKeyId !== undefined && preKeyId !== null) {
                await this.#store.removePreKey(preKeyId);
            }
            return plaintext;
        });
    }

    getRemoteRegistrationId(): Promise<number | undefined | null> {
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const record = await this.#getRecord(this.#remoteAddress.toString());
            if (record === undefined) return undefined;

            const openSession = record.getOpenSession();
            if (openSession === undefined) return null;

            return openSession?.registrationId ?? null;
        });
    }

    hasOpenSession(): Promise<boolean> {
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const record = await this.#getRecord(this.#remoteAddress.toString());
            if (record === undefined) return false;

            return record.hasOpenSession();
        });
    }

    closeOpenSessionForDevice(): Promise<void> {
        const address = this.#remoteAddress.toString();
        return queueJobForNumber(address, async () => {
            const record = await this.#getRecord(address);
            if (record === undefined || record.getOpenSession() === undefined) {
                return;
            }

            record.archiveCurrentState();
            return this.#store.storeSession(address, record.serialize());
        });
    }

    deleteAllSessionsForDevice(): Promise<void> {
        const address = this.#remoteAddress.toString();
        return queueJobForNumber(address, async () => {
            const record = await this.#getRecord(address);
            if (record === undefined) {
                return;
            }
            record.deleteAllSessions();
            return this.#store.storeSession(address, record.serialize());
        });
    }
}

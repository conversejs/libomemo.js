import { util } from "../helpers";
import { SessionRecord } from "./record";
import { queueJobForNumber } from "./lock";
import { internalCrypto, sign, encrypt, decrypt, HKDF } from "../crypto";
import { SessionBuilder } from "./builder";
import { OMEMOAddress } from "./address";
import { ChainType } from "../types";
import { getProtocolProfile, ProtocolProfile, MacContext, toExactBuffer } from "./protocol-profile";
import {
    EncryptResult,
    DecryptResult,
    SessionState,
    OMEMOStore,
    OMEMOVersion,
    Direction,
    Chain,
} from "./types";

/**
 * XEP-0384 MAX_SKIP: the max number of skipped message keys retained per
 * receiving chain. Once exceeded, the oldest (lowest-counter) keys are dropped
 * on a FIFO basis. This bounds the storage-flooding DoS described in the XEP's
 * "MAX_SKIP" / "deletion policy for skipped message keys" sections.
 *
 * The XEP wording is per-session; we cap per-chain (matching libsignal and the
 * library's existing per-chain pruning in record.ts), which is simpler and
 * serialization-compatible.
 *
 * This is independent of the per-message forward-jump cap (2000) in
 * #fillMessageKeys: that bounds the work a single message can force (CPU),
 * while this bounds the keys retained across messages (memory). The cap is
 * enforced by FIFO eviction regardless of the jump limit, so the two need no
 * particular relationship. The XEP RECOMMENDS ~1000 for both.
 */
const MAX_SKIPPED_MESSAGE_KEYS = 1000;

/** Encrypts and decrypts messages for established OMEMO sessions. */
export class SessionCipher {
    #remoteAddress: OMEMOAddress;
    #store: OMEMOStore;
    #profile: ProtocolProfile;

    constructor(store: OMEMOStore, remoteAddress: OMEMOAddress | string, version: OMEMOVersion) {
        this.#remoteAddress =
            typeof remoteAddress === "string"
                ? OMEMOAddress.fromString(remoteAddress)
                : remoteAddress;
        this.#store = store;
        this.#profile = getProtocolProfile(version);
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

        // KDF_CK: HMAC(chainKey, 0x01) -> message key, HMAC(chainKey, 0x02) -> next chain key.
        let key = chain.chainKey.key;
        const byteArray = new Uint8Array(1);
        byteArray[0] = 1;

        const messageKey = await sign(key, byteArray.buffer);
        byteArray[0] = 2;

        key = await sign(key, byteArray.buffer);
        chain.messageKeys[chain.chainKey.counter + 1] = messageKey;
        chain.chainKey.key = key;
        chain.chainKey.counter += 1;

        this.#trimSkippedMessageKeys(chain);

        return this.#fillMessageKeys(chain, counter);
    }

    /**
     * Enforce MAX_SKIPPED_MESSAGE_KEYS by discarding skipped keys FIFO. Keys are
     * only ever inserted by #fillMessageKeys, in strictly increasing counter
     * order, so the oldest key that can need evicting is always exactly
     * MAX_SKIPPED_MESSAGE_KEYS positions behind the one just inserted — no scan
     * needed. delete on an absent or negative key (chain shorter than the cap)
     * is a harmless no-op. This keeps the retained keys within a counter window
     * of width MAX_SKIPPED_MESSAGE_KEYS behind the chain's high-water mark.
     */
    #trimSkippedMessageKeys(chain: Chain): void {
        delete chain.messageKeys[chain.chainKey.counter - MAX_SKIPPED_MESSAGE_KEYS];
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
        const masterKey = await HKDF(sharedSecret, ratchet.rootKey, this.#profile.rootChainInfo);
        const ephemeralPublicKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
        const ephemeralKeyStr = util.toString(ephemeralPublicKey) as keyof SessionState;
        session[ephemeralKeyStr] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: sending ? ChainType.SENDING : ChainType.RECEIVING,
        };
        ratchet.rootKey = masterKey[0];
    }

    #macContext(
        session: SessionState,
        ourIdentityKey: ArrayBuffer,
        direction: Direction
    ): MacContext {
        return {
            ourIdentityKey,
            remoteIdentityKey: session.indexInfo.remoteIdentityKey,
            direction: direction === Direction.SENDING ? "sending" : "receiving",
            ad: session.ad,
        };
    }

    /**
     * The remote identity key in the form trust/fingerprints are keyed on: the
     * published Ed25519 form for versions that use it (omemo:2), otherwise the
     * internal Curve form. For Ed versions the Ed form is required — falling back
     * to the Curve form would silently key trust on the wrong bytes.
     */
    #remoteTrustKey(session: SessionState): ArrayBuffer {
        if (this.#profile.usesEdIdentityKey) {
            const ed = session.indexInfo.remoteIdentityKeyEd;
            if (!ed) {
                throw new Error(
                    `Session is missing the Ed25519 identity key required by ${this.#profile.version}`
                );
            }
            return ed;
        }
        return session.indexInfo.remoteIdentityKey;
    }

    async #doDecryptWhisperMessage(
        messageBytes: ArrayBuffer,
        session: SessionState | undefined
    ): Promise<DecryptResult> {
        if (!(messageBytes instanceof ArrayBuffer)) {
            throw new Error("Expected messageBytes to be an ArrayBuffer");
        }

        const parsed = await this.#profile.parseMessage(messageBytes);
        const remoteEphemeralKey = parsed.ephemeralKey;

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

        await this.#maybeStepRatchet(session, remoteEphemeralKey, parsed.previousCounter);
        const chain = session[util.toString(parsed.ephemeralKey) as keyof SessionState] as Chain;
        if (chain.chainType === ChainType.SENDING) {
            throw new Error("Tried to decrypt on a sending chain");
        }

        await this.#fillMessageKeys(chain, parsed.counter);

        const messageKey = chain.messageKeys[parsed.counter];
        if (messageKey === undefined) {
            const e = new Error(
                "Message key not found. The counter was repeated or the key was not filled."
            );
            e.name = "MessageCounterError";
            throw e;
        }
        delete chain.messageKeys[parsed.counter];

        const keys = await HKDF(messageKey, new ArrayBuffer(32), this.#profile.messageKeyInfo);

        const ourIdentityKey = await this.#store.getIdentityKeyPair();
        if (!ourIdentityKey) throw new Error("No identity keypair to verify MAC");

        await this.#profile.verifyMac(
            keys[1],
            parsed.encodedInner,
            this.#macContext(session, ourIdentityKey.pubKey, Direction.RECEIVING),
            parsed.mac
        );

        const plaintext = await decrypt(keys[0], parsed.ciphertext, keys[2].slice(0, 16));
        delete session.pendingPreKey;
        return {
            plaintext,
            ratchet: { counter: parsed.counter, key: parsed.ephemeralKey },
        };
    }

    async #decryptWithSessionList(
        buffer: ArrayBuffer,
        sessionList: SessionState[],
        errors: unknown[] = []
    ): Promise<{ result: DecryptResult; session: SessionState }> {
        if (sessionList.length === 0) {
            return Promise.reject(errors[0]);
        }

        const session = sessionList.pop()!;
        try {
            return {
                result: await this.#doDecryptWhisperMessage(buffer, session),
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

    /** Encrypt a message for the remote device. */
    encrypt(buffer: ArrayBuffer | string | Uint8Array): Promise<EncryptResult> {
        let buf: ArrayBuffer;
        if (!(buffer instanceof ArrayBuffer)) {
            if (typeof buffer === "string") {
                buf = new TextEncoder().encode(buffer).buffer;
            } else if (buffer instanceof Uint8Array) {
                buf = toExactBuffer(buffer);
            } else {
                throw new Error("Expected buffer to be an ArrayBuffer, string, or Uint8Array");
            }
        } else {
            buf = buffer;
        }

        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();

            const [ourIdentityKey, myRegistrationId, record] = await Promise.all([
                this.#store.getIdentityKeyPair(),
                this.#store.getLocalRegistrationId(),
                this.#getRecord(address),
            ]);

            if (!ourIdentityKey) throw new Error("Can't encrypt: no identity key");
            if (!record) throw new Error(`Can't encrypt: no record for ${address}`);

            const session = record.getOpenSession();
            if (!session) {
                throw new Error(`No session to encrypt message for ${address}`);
            }

            const ephemeralKey = session.currentRatchet.ephemeralKeyPair.pubKey;
            const chain = session[util.toString(ephemeralKey) as keyof SessionState] as Chain;
            if (chain.chainType === ChainType.RECEIVING) {
                throw new Error("Tried to encrypt on a receiving chain");
            }

            await this.#fillMessageKeys(chain, chain.chainKey.counter + 1);

            const keys = await HKDF(
                chain.messageKeys[chain.chainKey.counter],
                new ArrayBuffer(32),
                this.#profile.messageKeyInfo
            );
            delete chain.messageKeys[chain.chainKey.counter];

            const counter = chain.chainKey.counter;
            const previousCounter = session.currentRatchet.previousCounter;

            const ciphertext = await encrypt(keys[0], buf, keys[2].slice(0, 16));

            const encodedInner = await this.#profile.encodeInner({
                ephemeralKey,
                counter,
                previousCounter,
                ciphertext,
            });
            const mac = await this.#profile.computeMac(
                keys[1],
                encodedInner,
                this.#macContext(session, ourIdentityKey.pubKey, Direction.SENDING)
            );
            const result = await this.#profile.frameMessage(encodedInner, mac);

            const trustKey = this.#remoteTrustKey(session);
            const trusted = await this.#store.isTrustedIdentity(
                this.#remoteAddress.toString(),
                trustKey,
                Direction.SENDING
            );
            if (!trusted) {
                throw new Error("Identity key changed");
            }
            await this.#store.saveIdentity(this.#remoteAddress.toString(), trustKey);

            record.updateSessionState(session);
            await this.#store.storeSession(address, record.serialize());

            if (session.pendingPreKey !== undefined) {
                if (this.#profile.requiresRegistrationId && myRegistrationId === undefined) {
                    throw new Error("Can't encrypt key-exchange message: no local registrationId");
                }
                const kexBody = await this.#profile.encodeKeyExchange(
                    {
                        registrationId: myRegistrationId,
                        preKeyId: session.pendingPreKey.preKeyId,
                        signedPreKeyId: session.pendingPreKey.signedKeyId,
                        baseKey: session.pendingPreKey.baseKey,
                        ourIdentityKey,
                    },
                    result
                );
                return this.#profile.wrapResult(kexBody, true, session.registrationId);
            }
            return this.#profile.wrapResult(result, false, session.registrationId);
        });
    }

    /** Decrypt a regular (non-key-exchange) message using an existing session. */
    async decryptWhisperMessage(
        buffer: string | ArrayBuffer | Uint8Array,
        encoding: string
    ): Promise<DecryptResult> {
        const normalized = util.normalizeBuffer(buffer, encoding);
        const exact = toExactBuffer(normalized);
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();

            const record = await this.#getRecord(address);
            if (!record) throw new Error(`No record for device ${address}`);

            const { session, result } = await this.#decryptWithSessionList(
                exact,
                record.getSessions()
            );

            if (session.indexInfo.baseKey !== record.getOpenSession()!.indexInfo.baseKey) {
                record.archiveCurrentState();
                record.promoteState(session);
            }

            const trustKey = this.#remoteTrustKey(session);
            const trusted = await this.#store.isTrustedIdentity(
                this.#remoteAddress.toString(),
                trustKey,
                Direction.RECEIVING
            );
            if (!trusted) throw new Error("Identity key changed");

            await this.#store.saveIdentity(this.#remoteAddress.toString(), trustKey);
            record.updateSessionState(session);

            await this.#store.storeSession(address, record.serialize());

            return result;
        });
    }

    /** Decrypt a key-exchange message, establishing a new session if needed. */
    decryptPreKeyWhisperMessage(
        buffer: string | ArrayBuffer | Uint8Array,
        encoding: string
    ): Promise<DecryptResult> {
        const normalized = util.normalizeBuffer(buffer, encoding);
        const exact = toExactBuffer(normalized);

        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const address = this.#remoteAddress.toString();
            const parsed = await this.#profile.parseKeyExchange(exact);

            let record = await this.#getRecord(address);
            if (!record) {
                if (this.#profile.requiresRegistrationId && parsed.registrationId === undefined) {
                    throw new Error("No registrationId");
                }
                record = new SessionRecord();
            }
            const builder = new SessionBuilder(
                this.#store,
                this.#remoteAddress,
                this.#profile.version
            );

            const preKeyId = await builder.processV3(record, parsed);

            const session = record.getSessionByBaseKey(parsed.baseKey);
            const result = await this.#doDecryptWhisperMessage(parsed.message, session);
            record.updateSessionState(session!);
            await this.#store.storeSession(address, record.serialize());

            if (preKeyId !== undefined && preKeyId !== null) {
                await this.#store.removePreKey(preKeyId);
            }
            return result;
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

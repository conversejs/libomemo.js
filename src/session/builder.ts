import { util } from "../helpers";
import { SessionRecord } from "./record";
import { queueJobForNumber } from "./lock";
import { internalCrypto, HKDF } from "../crypto";
import { OMEMOAddress } from "./address";
import { BaseKeyType, ChainType, KeyPair } from "../types";
import { PreKeyBundle, SessionState, SignalProtocolStore } from "./types";

/**
 * Establishes a new Signal Protocol session from a PreKey bundle.
 */
export class SessionBuilder {
    #remoteAddress: OMEMOAddress;
    #storage: SignalProtocolStore;

    constructor(storage: SignalProtocolStore, remoteAddress: OMEMOAddress | string) {
        this.#remoteAddress =
            typeof remoteAddress === "string"
                ? OMEMOAddress.fromString(remoteAddress)
                : remoteAddress;
        this.#storage = storage;
    }

    processPreKey(device: PreKeyBundle): Promise<void> {
        return queueJobForNumber(this.#remoteAddress.toString(), async () => {
            const trusted = await this.#storage.isTrustedIdentity(
                this.#remoteAddress.getName(),
                device.identityKey,
                this.#storage.Direction.SENDING
            );

            if (!trusted) {
                throw new Error("Identity key changed");
            }

            await internalCrypto.Ed25519Verify(
                device.identityKey,
                device.signedPreKey.publicKey,
                device.signedPreKey.signature
            );

            const baseKey = await internalCrypto.createKeyPair();
            const devicePreKey = device.preKey ? device.preKey.publicKey : undefined;
            const session = await this.#initSession(
                true,
                baseKey,
                undefined,
                device.identityKey,
                devicePreKey,
                device.signedPreKey.publicKey,
                device.registrationId
            );

            session.pendingPreKey = {
                signedKeyId: device.signedPreKey.keyId,
                baseKey: baseKey.pubKey,
            };

            if (device.preKey) {
                session.pendingPreKey.preKeyId = device.preKey.keyId;
            }

            const address = this.#remoteAddress.toString();
            const serialized = await this.#storage.loadSession(address);

            const record =
                serialized !== undefined
                    ? SessionRecord.deserialize(serialized)
                    : new SessionRecord();

            record.archiveCurrentState();
            record.updateSessionState(session);
            await Promise.all([
                this.#storage.storeSession(address, record.serialize()),
                this.#storage.saveIdentity(
                    this.#remoteAddress.toString(),
                    session.indexInfo.remoteIdentityKey
                ),
            ]);
            return;
        });
    }

    async processV3(record: SessionRecord, message: any): Promise<number | undefined> {
        if (record.getSessionByBaseKey(message.baseKey)) {
            console.log("Duplicate PreKeyMessage for session");
            return;
        }

        const identityKeyAB = message.identityKey.slice().buffer as ArrayBuffer;

        const trusted = await this.#storage.isTrustedIdentity(
            this.#remoteAddress.getName(),
            identityKeyAB,
            this.#storage.Direction.RECEIVING
        );

        if (!trusted) {
            const e = new Error("Unknown identity key");
            (e as any).identityKey = identityKeyAB;
            throw e;
        }

        const results = await Promise.all([
            this.#storage.loadPreKey(message.preKeyId),
            this.#storage.loadSignedPreKey(message.signedPreKeyId),
        ]);

        const preKeyPair = results[0];
        const signedPreKeyPair = results[1];
        const session = record.getOpenSession();

        if (signedPreKeyPair === undefined) {
            if (session !== undefined && (session as any).currentRatchet !== undefined) {
                return;
            } else {
                throw new Error("Missing Signed PreKey for PreKeyWhisperMessage");
            }
        }

        if (session !== undefined) {
            record.archiveCurrentState();
        }

        if (message.preKeyId && !preKeyPair) {
            console.log("Invalid prekey id", message.preKeyId);
        }

        const baseKeyAB = message.baseKey.slice().buffer as ArrayBuffer;
        const newSession = await this.#initSession(
            false,
            preKeyPair ? preKeyPair.keyPair : undefined,
            signedPreKeyPair ? signedPreKeyPair.keyPair : undefined,
            identityKeyAB,
            baseKeyAB,
            undefined,
            message.registrationId
        );

        record.updateSessionState(newSession);

        await this.#storage.saveIdentity(this.#remoteAddress.toString(), identityKeyAB);
        return message.preKeyId;
    }

    async #initSession(
        isInitiator: boolean,
        ourEphemeralKey: KeyPair | undefined,
        ourSignedKey: KeyPair | undefined,
        theirIdentityPubKey: ArrayBuffer,
        theirEphemeralPubKey: ArrayBuffer | undefined,
        theirSignedPubKey: ArrayBuffer | undefined,
        registrationId: number
    ): Promise<SessionState> {
        const ourIdentityKey = await this.#storage.getIdentityKeyPair();

        if (isInitiator) {
            if (ourSignedKey !== undefined) {
                throw new Error("Invalid call to initSession");
            }
            ourSignedKey = ourEphemeralKey;
        } else {
            if (theirSignedPubKey !== undefined) {
                throw new Error("Invalid call to initSession");
            }
            theirSignedPubKey = theirEphemeralPubKey;
        }

        let sharedSecret: Uint8Array;
        if (ourEphemeralKey === undefined || theirEphemeralPubKey === undefined) {
            sharedSecret = new Uint8Array(32 * 4);
        } else {
            sharedSecret = new Uint8Array(32 * 5);
        }

        for (let i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff;
        }

        const ecRes = await Promise.all([
            internalCrypto.ECDHE(theirSignedPubKey!, ourIdentityKey.privKey),
            internalCrypto.ECDHE(theirIdentityPubKey, ourSignedKey!.privKey),
            internalCrypto.ECDHE(theirSignedPubKey!, ourSignedKey!.privKey),
        ]);

        if (isInitiator) {
            sharedSecret.set(new Uint8Array(ecRes[0]), 32);
            sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2);
        } else {
            sharedSecret.set(new Uint8Array(ecRes[0]), 32 * 2);
            sharedSecret.set(new Uint8Array(ecRes[1]), 32);
        }
        sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3);

        if (ourEphemeralKey !== undefined && theirEphemeralPubKey !== undefined) {
            const ecRes4 = await internalCrypto.ECDHE(
                theirEphemeralPubKey,
                ourEphemeralKey.privKey
            );
            sharedSecret.set(new Uint8Array(ecRes4), 32 * 4);
        }

        const masterKey = await HKDF(
            sharedSecret.buffer as ArrayBuffer,
            new ArrayBuffer(32),
            "WhisperText"
        );

        const session: SessionState = {
            registrationId: registrationId,
            currentRatchet: {
                rootKey: masterKey[0],
                lastRemoteEphemeralKey: theirSignedPubKey!,
                previousCounter: 0,
                ephemeralKeyPair: ourSignedKey!,
            },
            indexInfo: {
                remoteIdentityKey: theirIdentityPubKey,
                closed: -1,
            },
            oldRatchetList: [],
        };

        if (isInitiator) {
            session.indexInfo.baseKey = ourEphemeralKey!.pubKey;
            session.indexInfo.baseKeyType = BaseKeyType.OURS;
            const ourSendingEphemeralKey = await internalCrypto.createKeyPair();
            session.currentRatchet.ephemeralKeyPair = ourSendingEphemeralKey;
            await this.#calculateSendingRatchet(session, theirSignedPubKey!);
        } else {
            session.indexInfo.baseKey = theirEphemeralPubKey!;
            session.indexInfo.baseKeyType = BaseKeyType.THEIRS;
            session.currentRatchet.ephemeralKeyPair = ourSignedKey!;
        }
        return session;
    }

    async #calculateSendingRatchet(session: SessionState, remoteKey: ArrayBuffer): Promise<void> {
        const ratchet = session.currentRatchet;

        const sharedSecret = await internalCrypto.ECDHE(
            remoteKey,
            util.toArrayBuffer(ratchet.ephemeralKeyPair.privKey)!
        );

        const masterKey = await HKDF(
            sharedSecret,
            util.toArrayBuffer(ratchet.rootKey)!,
            "WhisperRatchet"
        );

        session[util.toString(ratchet.ephemeralKeyPair.pubKey)] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: ChainType.SENDING,
        };
        ratchet.rootKey = masterKey[0];
    }
}

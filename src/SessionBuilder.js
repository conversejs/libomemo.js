/**
 * Establishes a new Signal Protocol session from a PreKey bundle.
 *
 * On the sending side, {@link SessionBuilder#processPreKey} consumes the
 * recipient's PreKey bundle (identity key, signed PreKey, optional one-time
 * PreKey) and runs the triple Diffie-Hellman key agreement to produce an
 * initial session state, which is persisted via the provided
 * {@link SignalProtocolStore}.
 *
 * On the receiving side, {@link SessionBuilder#processV3} processes an
 * incoming PreKeyWhisperMessage, retrieves the corresponding local PreKey
 * records, performs the shared-secret derivation, and updates the session
 * record so the message can subsequently be decrypted by
 * {@link SessionCipher}.
 *
 * @param {SignalProtocolStore} storage  Storage backend for identity keys,
 *                                       PreKeys, and session records.
 * @param {SignalProtocolAddress} remoteAddress  Address of the remote party
 *                                               (name + device ID) with whom
 *                                               the session is being established.
 */
class SessionBuilder {
    /**
     * @param {SignalProtocolStore} storage  Storage backend for identity keys,
     *                                       PreKeys, and session records.
     * @param {SignalProtocolAddress} remoteAddress  Address of the remote party.
     */
    constructor(storage, remoteAddress) {
        this.remoteAddress = remoteAddress;
        this.storage = storage;
    }

    /**
     * Processes a remote PreKey bundle to establish a session as the initiator.
     *
     * Validates the identity key and signed PreKey signature, then performs the
     * X3DH key agreement.  The resulting session state is archived into the
     * session record and persisted to storage.  The base key and PreKey /
     * signed PreKey IDs are recorded as a pending PreKey so the session can be
     * identified on the receiving end.
     *
     * @param {Object} device                 Remote PreKey bundle.
     * @param {ArrayBuffer} device.identityKey       Remote identity public key.
     * @param {Object} device.signedPreKey           Remote signed PreKey.
     * @param {number} device.signedPreKey.keyId     ID of the signed PreKey.
     * @param {ArrayBuffer} device.signedPreKey.publicKey  Public key data.
     * @param {ArrayBuffer} device.signedPreKey.signature  Ed25519 signature.
     * @param {Object} [device.preKey]               Remote one-time PreKey.
     * @param {number} device.preKey.keyId           ID of the one-time PreKey.
     * @param {ArrayBuffer} device.preKey.publicKey  Public key data.
     * @param {number} device.registrationId         Remote registration ID.
     * @returns {Promise<void>}
     */
    processPreKey(device) {
        return Internal.SessionLock.queueJobForNumber(this.remoteAddress.toString(), async () => {
            const trusted = await this.storage.isTrustedIdentity(
                this.remoteAddress.getName(),
                device.identityKey,
                this.storage.Direction.SENDING
            );

            if (!trusted) {
                throw new Error("Identity key changed");
            }

            await Internal.crypto.Ed25519Verify(
                device.identityKey,
                device.signedPreKey.publicKey,
                device.signedPreKey.signature
            );

            const baseKey = await Internal.crypto.createKeyPair();
            const devicePreKey = device.preKey ? device.preKey.publicKey : undefined;
            const session = await this.initSession(
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

            const address = this.remoteAddress.toString();
            const serialized = await this.storage.loadSession(address);

            const record =
                serialized !== undefined
                    ? Internal.SessionRecord.deserialize(serialized)
                    : new Internal.SessionRecord();

            record.archiveCurrentState();
            record.updateSessionState(session);
            return Promise.all([
                this.storage.storeSession(address, record.serialize()),
                this.storage.saveIdentity(
                    this.remoteAddress.toString(),
                    session.indexInfo.remoteIdentityKey
                ),
            ]);
        });
    }

    /**
     * Processes an incoming PreKeyWhisperMessage as the session responder.
     *
     * Verifies the sender's identity key, loads the corresponding local PreKey
     * and signed PreKey records, then performs the X3DH key agreement to
     * derive a new session state.  The session record is updated in memory;
     * the caller is responsible for persisting it after the associated
     * WhisperMessage has been successfully decrypted.
     *
     * @param {Internal.SessionRecord} record   Current session record for the
     *                                          remote address.
     * @param {Object} message                  Deserialised PreKeyWhisperMessage.
     * @param {number} [message.preKeyId]       ID of the consumed one-time PreKey.
     * @param {number} message.signedPreKeyId   ID of the consumed signed PreKey.
     * @param {Uint8Array} message.baseKey      Ephemeral base key from the sender.
     * @param {Uint8Array} message.identityKey  Sender's identity public key.
     * @param {number} message.registrationId   Sender's registration ID.
     * @returns {Promise<number|undefined>}     The consumed PreKey ID, or
     *                                          undefined if a duplicate message
     *                                          was received.
     * @throws {Error} If the identity key is not trusted or the required
     *                 signed PreKey cannot be found.
     */
    async processV3(record, message) {
        if (record.getSessionByBaseKey(message.baseKey)) {
            console.log("Duplicate PreKeyMessage for session");
            return;
        }

        // https://github.com/protobufjs/protobuf.js/issues/852#issuecomment-369895366
        const identityKeyAB = message.identityKey.slice().buffer;

        const trusted = await this.storage.isTrustedIdentity(
            this.remoteAddress.getName(),
            identityKeyAB,
            this.storage.Direction.RECEIVING
        );

        if (!trusted) {
            const e = new Error("Unknown identity key");
            e.identityKey = identityKeyAB;
            throw e;
        }

        const results = await Promise.all([
            this.storage.loadPreKey(message.preKeyId),
            this.storage.loadSignedPreKey(message.signedPreKeyId),
        ]);

        const preKeyPair = results[0];
        const signedPreKeyPair = results[1];
        const session = record.getOpenSession();

        if (signedPreKeyPair === undefined) {
            // Session may or may not be the right one, but if its not, we;
            // can't do anything about it ...fall through and let
            // decryptWhisperMessage handle that case
            if (session !== undefined && session.currentRatchet !== undefined) {
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

        const baseKeyAB = message.baseKey.slice().buffer;
        const newSession = await this.initSession(
            false,
            preKeyPair,
            signedPreKeyPair,
            identityKeyAB,
            baseKeyAB,
            undefined,
            message.registrationId
        );

        // Note that the session is not actually saved until the very
        // end of decryptWhisperMessage ... to ensure that the sender
        // actually holds the private keys for all reported pubkeys
        record.updateSessionState(newSession);

        await this.storage.saveIdentity(this.remoteAddress.toString(), identityKeyAB);
        return message.preKeyId;
    }

    /**
     * Performs the core X3DH key agreement and returns a new session state.
     *
     * Computes up to four ECDH shared secrets (3DH + optional 4th) and feeds
     * them through HKDF to derive the initial root key.  On the initiator side
     * the first sending ratchet is advanced immediately.
     *
     * @param {boolean} isInitiator         Whether we initiated the session.
     * @param {KeyPair} ourEphemeralKey     Our ephemeral key pair (initiator: baseKey,
     *                                      responder: one-time PreKey).
     * @param {KeyPair} ourSignedKey        Our signed PreKey key pair
     *                                      (responder only; initiator passes undefined).
     * @param {ArrayBuffer} theirIdentityPubKey   Remote identity public key.
     * @param {ArrayBuffer} theirEphemeralPubKey  Remote ephemeral public key (initiator:
     *                                            one-time PreKey; responder: baseKey).
     * @param {ArrayBuffer} theirSignedPubKey     Remote signed PreKey public key.
     * @param {number} registrationId             Remote registration ID.
     * @returns {Promise<Object>}   The new session state object.
     * @private
     */
    async initSession(
        isInitiator,
        ourEphemeralKey,
        ourSignedKey,
        theirIdentityPubKey,
        theirEphemeralPubKey,
        theirSignedPubKey,
        registrationId
    ) {
        const ourIdentityKey = await this.storage.getIdentityKeyPair();

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

        let sharedSecret;
        if (ourEphemeralKey === undefined || theirEphemeralPubKey === undefined) {
            sharedSecret = new Uint8Array(32 * 4);
        } else {
            sharedSecret = new Uint8Array(32 * 5);
        }

        for (let i = 0; i < 32; i++) {
            sharedSecret[i] = 0xff;
        }

        const ecRes = await Promise.all([
            Internal.crypto.ECDHE(theirSignedPubKey, ourIdentityKey.privKey),
            Internal.crypto.ECDHE(theirIdentityPubKey, ourSignedKey.privKey),
            Internal.crypto.ECDHE(theirSignedPubKey, ourSignedKey.privKey),
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
            const ecRes4 = await Internal.crypto.ECDHE(
                theirEphemeralPubKey,
                ourEphemeralKey.privKey
            );
            sharedSecret.set(new Uint8Array(ecRes4), 32 * 4);
        }

        const masterKey = await Internal.HKDF(
            sharedSecret.buffer,
            new ArrayBuffer(32),
            "WhisperText"
        );

        const session = {
            registrationId: registrationId,
            currentRatchet: {
                rootKey: masterKey[0],
                lastRemoteEphemeralKey: theirSignedPubKey,
                previousCounter: 0,
            },
            indexInfo: {
                remoteIdentityKey: theirIdentityPubKey,
                closed: -1,
            },
            oldRatchetList: [],
        };

        // If we're initiating we go ahead and set our first sending ephemeral key now,
        // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key
        if (isInitiator) {
            session.indexInfo.baseKey = ourEphemeralKey.pubKey;
            session.indexInfo.baseKeyType = Internal.BaseKeyType.OURS;
            const ourSendingEphemeralKey = await Internal.crypto.createKeyPair();
            session.currentRatchet.ephemeralKeyPair = ourSendingEphemeralKey;
            await this.calculateSendingRatchet(session, theirSignedPubKey);
        } else {
            session.indexInfo.baseKey = theirEphemeralPubKey;
            session.indexInfo.baseKeyType = Internal.BaseKeyType.THEIRS;
            session.currentRatchet.ephemeralKeyPair = ourSignedKey;
        }
        return session;
    }

    /**
     * Advances the sending ratchet using the remote party's signed PreKey.
     *
     * Performs an ECDH between our initial ephemeral key pair and the remote
     * signed PreKey, then HKDF-expands the result together with the current
     * root key to produce a new root key and a sending chain key.  The
     * sending chain and its initial message-keys placeholder are attached to
     * the session object keyed by our ephemeral public key.
     *
     * @param {Object} session       Session state returned by {@link initSession}.
     * @param {ArrayBuffer} remoteKey   Remote signed PreKey public key.
     * @returns {Promise<void>}
     * @private
     */
    async calculateSendingRatchet(session, remoteKey) {
        const ratchet = session.currentRatchet;

        const sharedSecret = await Internal.crypto.ECDHE(
            remoteKey,
            util.toArrayBuffer(ratchet.ephemeralKeyPair.privKey)
        );

        const masterKey = await Internal.HKDF(
            sharedSecret,
            util.toArrayBuffer(ratchet.rootKey),
            "WhisperRatchet"
        );

        session[util.toString(ratchet.ephemeralKeyPair.pubKey)] = {
            messageKeys: {},
            chainKey: { counter: -1, key: masterKey[1] },
            chainType: Internal.ChainType.SENDING,
        };
        ratchet.rootKey = masterKey[0];
    }
}

libomemo.SessionBuilder = function (storage, remoteAddress) {
    const builder = new SessionBuilder(storage, remoteAddress);
    this.processPreKey = (device) => builder.processPreKey(device);
    this.processV3 = (record, message) => builder.processV3(record, message);
};

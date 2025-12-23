class SessionBuilder {
    constructor(storage, remoteAddress) {
        this.remoteAddress = remoteAddress;
        this.storage = storage;
    }

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

libsignal.SessionBuilder = function (storage, remoteAddress) {
    const builder = new SessionBuilder(storage, remoteAddress);
    this.processPreKey = (device) => builder.processPreKey(device);
    this.processV3 = (record, message) => builder.processV3(record, message);
};

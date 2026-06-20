import { sign, verifyMAC, internalCrypto } from "../crypto";
import { loadProtocolMessages, loadOMEMOMessages } from "../protobufs";
import { KeyPair } from "../types";
import {
    EncryptResult,
    OMEMOVersion,
    WhisperMessageProto,
    PreKeyWhisperMessageProto,
    OMEMOMessageProto,
    OMEMOKeyExchangeProto,
} from "./types";

export type { OMEMOVersion };

/** A remote identity key normalised to the library's internal forms. */
export interface NormalizedIdentityKey {
    /** 33-byte 0x05-prefixed Curve25519 form (for DH, signature verification, storage). */
    curve: ArrayBuffer;
    /** 32-byte Ed25519 form (omemo:2 only, for the associated data). */
    ed?: ArrayBuffer;
}

/** Version byte prepended to every 0.3.0 message: `(3 << 4) | 3`. */
const V3_VERSION_BYTE = (3 << 4) | 3;

/** Parts of an outgoing ratchet message, using internal key forms. */
export type RatchetMessageParts = {
    /** Ratchet public key (internal 33-byte 0x05-prefixed curve key). */
    ephemeralKey: ArrayBuffer;
    counter: number;
    previousCounter: number;
    ciphertext: ArrayBuffer;
};

/** A decoded incoming ratchet message. */
export type ParsedRatchetMessage = RatchetMessageParts & {
    /** The serialised inner message, used as MAC input. */
    encodedInner: Uint8Array;
    /** The MAC carried with the message. */
    mac: ArrayBuffer;
};

/** Everything a profile may need to build/verify the message MAC. */
export interface MacContext {
    /** Our identity key, internal 33-byte curve form (0.3.0). */
    ourIdentityKey: ArrayBuffer;
    /** Remote identity key, internal 33-byte curve form (0.3.0). */
    remoteIdentityKey: ArrayBuffer;
    /** Message direction (0.3.0 swaps the identity-key prefix by direction). */
    direction: "sending" | "receiving";
    /** Session-fixed associated data (omemo:2). */
    ad?: ArrayBuffer;
}

/** Parts of an outgoing key-exchange message. */
export interface KeyExchangeParts {
    /** Our local registrationId. Required by 0.3.0; unused (and absent) for omemo:2. */
    registrationId?: number;
    preKeyId?: number;
    signedPreKeyId: number;
    /** Our base/ephemeral key (internal 33-byte curve form). */
    baseKey: ArrayBuffer;
    /** Our identity key pair; the profile derives the correct wire form for `ik`. */
    ourIdentityKey: KeyPair;
}

/** A decoded incoming key-exchange message. */
export interface ParsedKeyExchange {
    registrationId?: number;
    preKeyId?: number;
    signedPreKeyId: number;
    /** Remote base/ephemeral key, normalised to the internal 33-byte curve form. */
    baseKey: ArrayBuffer;
    /** Remote identity key, internal 33-byte curve form (for DH/storage). */
    identityKey: ArrayBuffer;
    /** Remote identity key in 32-byte Ed25519 form (omemo:2, for the AD). */
    identityKeyEd?: ArrayBuffer;
    /** The framed ratchet message to decrypt. */
    message: ArrayBuffer;
}

/**
 * Encapsulates everything that differs between OMEMO versions: HKDF info
 * strings, MAC length/associated-data, the wire protobufs, and result framing.
 * The double-ratchet mechanics in {@link SessionCipher}/{@link SessionBuilder}
 * are identical across versions and stay outside the profile.
 */
export interface ProtocolProfile {
    version: OMEMOVersion;
    /**
     * Whether a key-exchange message carries a registrationId on the wire that is
     * required to create a new session. 0.3.0 encodes it in the
     * PreKeyWhisperMessage; omemo:2 has no such field (the device id serves that
     * role), so it is derived rather than required.
     */
    requiresRegistrationId: boolean;
    /**
     * Whether the remote identity key is published in a separate Ed25519 form
     * that trust/fingerprints are keyed on. omemo:2 transfers the IdentityKey as
     * Ed25519 (kept alongside the internal Curve form); 0.3.0 has only the Curve
     * form. When true, sessions are expected to carry `remoteIdentityKeyEd`.
     */
    usesEdIdentityKey: boolean;
    /** HKDF info for the X3DH master secret (session init). */
    x3dhInfo: string;
    /** HKDF info for the root-key ratchet. */
    rootChainInfo: string;
    /** HKDF info for per-message key material. */
    messageKeyInfo: string;

    /** Serialise the inner ratchet message (WhisperMessage / OMEMOMessage). */
    encodeInner(parts: RatchetMessageParts): Promise<Uint8Array>;
    /** Compute the (already-truncated) MAC over the encoded inner message. */
    computeMac(
        authKey: ArrayBuffer,
        encodedInner: Uint8Array,
        ctx: MacContext
    ): Promise<ArrayBuffer>;
    /** Verify the MAC over the encoded inner message; throws on mismatch. */
    verifyMac(
        authKey: ArrayBuffer,
        encodedInner: Uint8Array,
        ctx: MacContext,
        mac: ArrayBuffer
    ): Promise<void>;
    /** Frame the final ratchet-message body (version byte + MAC, or OMEMOAuthenticatedMessage). */
    frameMessage(encodedInner: Uint8Array, mac: ArrayBuffer): Promise<Uint8Array>;
    /** Parse an incoming ratchet-message body. */
    parseMessage(bytes: ArrayBuffer): Promise<ParsedRatchetMessage>;

    /** Wrap an already-framed ratchet message in a key-exchange message body. */
    encodeKeyExchange(parts: KeyExchangeParts, framedMessage: Uint8Array): Promise<Uint8Array>;
    /** Parse an incoming key-exchange message body. */
    parseKeyExchange(bytes: ArrayBuffer): Promise<ParsedKeyExchange>;

    /** Build the {@link EncryptResult} returned to the consumer. */
    wrapResult(body: Uint8Array, isKeyExchange: boolean, registrationId: number): EncryptResult;

    /**
     * Compute the session-fixed associated data for omemo:2 (or `undefined` for
     * 0.3.0, which derives the MAC prefix per message instead). `AD = IK_A ‖ IK_B`
     * in Ed25519 form, ordered initiator-first.
     */
    buildAssociatedData(
        ourIdentityKey: KeyPair,
        remoteIdentityKeyEd: ArrayBuffer | undefined,
        isInitiator: boolean
    ): Promise<ArrayBuffer | undefined>;

    /**
     * Normalise a remote identity key received on the wire (from a PreKey bundle)
     * into the library's internal forms. For omemo:2 the wire form is Ed25519 and
     * is converted to its Curve25519 equivalent for DH/storage.
     */
    normalizeRemoteIdentityKey(wireKey: ArrayBuffer): Promise<NormalizedIdentityKey>;

    /**
     * The exact bytes of a signed-pre-key public key that the identity key signs
     * over (`Sig(IK, Encode(SPK))`). 0.3.0 signs the 33-byte 0x05-prefixed form;
     * omemo:2 signs the raw 32-byte Curve25519 (Montgomery) form, matching
     * libomemo-c.
     */
    signedPreKeySignatureData(publicKey: ArrayBuffer): ArrayBuffer;

    /**
     * Normalise a (signed-)pre-key public received on the wire (from a PreKey
     * bundle) into the library's internal 33-byte 0x05-prefixed curve form. 0.3.0
     * publishes that form already; omemo:2 transfers the raw 32-byte curve form
     * and restores the prefix here. This mirrors the wire→internal normalisation
     * the profile already applies to ratchet/base keys on the message paths.
     */
    normalizeRemotePreKey(wireKey: ArrayBuffer): ArrayBuffer;
}

/**
 * Copy a typed-array view into a fresh, exactly-sized ArrayBuffer.
 *
 * Necessary because protobufjs `.finish()` returns a Node `Buffer` whose
 * `.slice()` is `subarray` (a view sharing the backing pool), so `.buffer`
 * would expose unrelated memory. `ArrayBuffer.prototype.slice` always copies.
 */
export function toExactBuffer(view: Uint8Array): ArrayBuffer {
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

/** Concatenate ArrayBuffers into one. */
function concat(buffers: ArrayBuffer[]): ArrayBuffer {
    const total = buffers.reduce((n, b) => n + b.byteLength, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const b of buffers) {
        out.set(new Uint8Array(b), offset);
        offset += b.byteLength;
    }
    return out.buffer;
}

/** Drop the 0x05 type prefix from a curve public key, returning the raw 32 bytes. */
function stripKeyType(key: ArrayBuffer): ArrayBuffer {
    const bytes = new Uint8Array(key);
    if (bytes.byteLength === 33 && bytes[0] === 5) {
        return key.slice(1);
    }
    return key;
}

/** Add the 0x05 type prefix to a raw 32-byte curve public key. */
function addKeyType(key: ArrayBuffer): ArrayBuffer {
    const bytes = new Uint8Array(key);
    if (bytes.byteLength === 32) {
        const out = new Uint8Array(33);
        out[0] = 5;
        out.set(bytes, 1);
        return out.buffer;
    }
    return key;
}

/**
 * Build the 0.3.0 MAC input: `[senderIK(33) ‖ receiverIK(33) ‖ versionByte(1) ‖ message]`.
 * The identity-key prefix is ordered by direction (always sender-then-receiver).
 */
function buildV3MacInput(encodedInner: Uint8Array, ctx: MacContext): ArrayBuffer {
    const first = ctx.direction === "sending" ? ctx.ourIdentityKey : ctx.remoteIdentityKey;
    const second = ctx.direction === "sending" ? ctx.remoteIdentityKey : ctx.ourIdentityKey;
    const macInput = new Uint8Array(encodedInner.byteLength + 33 * 2 + 1);
    macInput.set(new Uint8Array(first));
    macInput.set(new Uint8Array(second), 33);
    macInput[33 * 2] = V3_VERSION_BYTE;
    macInput.set(encodedInner, 33 * 2 + 1);
    return macInput.buffer;
}

/** Profile for OMEMO 0.3.0 (libsignal "v3" wire format). */
const OMEMO_0_3_0: ProtocolProfile = {
    version: "eu.siacs.conversations.axolotl",
    requiresRegistrationId: true,
    usesEdIdentityKey: false,
    x3dhInfo: "WhisperText",
    rootChainInfo: "WhisperRatchet",
    messageKeyInfo: "WhisperMessageKeys",

    async encodeInner(parts: RatchetMessageParts): Promise<Uint8Array> {
        const { WhisperMessage } = await loadProtocolMessages();
        const msg = WhisperMessage.create({
            ephemeralKey: new Uint8Array(parts.ephemeralKey),
            counter: parts.counter,
            previousCounter: parts.previousCounter,
            ciphertext: new Uint8Array(parts.ciphertext),
        }) as unknown as WhisperMessageProto;
        return WhisperMessage.encode(msg).finish();
    },

    async computeMac(
        authKey: ArrayBuffer,
        encodedInner: Uint8Array,
        ctx: MacContext
    ): Promise<ArrayBuffer> {
        const fullMac = await sign(authKey, buildV3MacInput(encodedInner, ctx));
        return fullMac.slice(0, 8);
    },

    async verifyMac(
        authKey: ArrayBuffer,
        encodedInner: Uint8Array,
        ctx: MacContext,
        mac: ArrayBuffer
    ): Promise<void> {
        await verifyMAC(buildV3MacInput(encodedInner, ctx), authKey, mac, 8);
    },

    async frameMessage(encodedInner: Uint8Array, mac: ArrayBuffer): Promise<Uint8Array> {
        const result = new Uint8Array(encodedInner.byteLength + 1 + mac.byteLength);
        result[0] = V3_VERSION_BYTE;
        result.set(encodedInner, 1);
        result.set(new Uint8Array(mac), encodedInner.byteLength + 1);
        return result;
    },

    async parseMessage(bytes: ArrayBuffer): Promise<ParsedRatchetMessage> {
        const version = new Uint8Array(bytes)[0];
        if ((version & 0xf) > 3 || version >> 4 < 3) {
            throw new Error("Incompatible version number on WhisperMessage");
        }
        const encodedInner = new Uint8Array(bytes.slice(1, bytes.byteLength - 8));
        const mac = bytes.slice(bytes.byteLength - 8, bytes.byteLength);

        const { WhisperMessage } = await loadProtocolMessages();
        const message = WhisperMessage.decode(encodedInner) as unknown as WhisperMessageProto;
        return {
            ephemeralKey: toExactBuffer(message.ephemeralKey),
            counter: message.counter,
            previousCounter: message.previousCounter,
            ciphertext: toExactBuffer(message.ciphertext),
            encodedInner,
            mac,
        };
    },

    async encodeKeyExchange(
        parts: KeyExchangeParts,
        framedMessage: Uint8Array
    ): Promise<Uint8Array> {
        const { PreKeyWhisperMessage } = await loadProtocolMessages();
        const preKeyMsg = PreKeyWhisperMessage.create({
            baseKey: new Uint8Array(parts.baseKey),
            identityKey: new Uint8Array(parts.ourIdentityKey.pubKey),
            message: framedMessage,
            preKeyId: parts.preKeyId ? parts.preKeyId : undefined,
            registrationId: parts.registrationId,
            signedPreKeyId: parts.signedPreKeyId,
        });
        const encoded = PreKeyWhisperMessage.encode(preKeyMsg).finish();
        const out = new Uint8Array(encoded.length + 1);
        out[0] = V3_VERSION_BYTE;
        out.set(encoded, 1);
        return out;
    },

    async parseKeyExchange(bytes: ArrayBuffer): Promise<ParsedKeyExchange> {
        const version = new Uint8Array(bytes)[0];
        if ((version & 0xf) > 3 || version >> 4 < 3) {
            throw new Error("Incompatible version number on PreKeyWhisperMessage");
        }
        const { PreKeyWhisperMessage } = await loadProtocolMessages();
        const proto = PreKeyWhisperMessage.decode(
            new Uint8Array(bytes.slice(1))
        ) as unknown as PreKeyWhisperMessageProto;
        return {
            registrationId: proto.registrationId,
            preKeyId: proto.preKeyId,
            signedPreKeyId: proto.signedPreKeyId,
            baseKey: toExactBuffer(proto.baseKey),
            identityKey: toExactBuffer(proto.identityKey),
            message: toExactBuffer(proto.message),
        };
    },

    wrapResult(body: Uint8Array, isKeyExchange: boolean, registrationId: number): EncryptResult {
        return {
            type: isKeyExchange ? 3 : 1,
            body: bufferToBinaryString(body),
            registrationId,
        };
    },

    async buildAssociatedData(): Promise<ArrayBuffer | undefined> {
        return undefined;
    },

    async normalizeRemoteIdentityKey(wireKey: ArrayBuffer): Promise<NormalizedIdentityKey> {
        return { curve: wireKey };
    },

    signedPreKeySignatureData(publicKey: ArrayBuffer): ArrayBuffer {
        return publicKey;
    },

    normalizeRemotePreKey(wireKey: ArrayBuffer): ArrayBuffer {
        // 0.3.0 publishes the 33-byte 0x05-prefixed form; a raw 32-byte key is
        // malformed and is left to fail closed on the DH path.
        return wireKey;
    },
};

/** Profile for OMEMO 2 (urn:xmpp:omemo:2). */
const OMEMO_2: ProtocolProfile = {
    version: "urn:xmpp:omemo:2",
    requiresRegistrationId: false,
    usesEdIdentityKey: true,
    x3dhInfo: "OMEMO X3DH",
    rootChainInfo: "OMEMO Root Chain",
    messageKeyInfo: "OMEMO Message Key Material",

    async encodeInner(parts: RatchetMessageParts): Promise<Uint8Array> {
        const { OMEMOMessage } = await loadOMEMOMessages();
        // dh_pub is the raw 32-byte curve key (RFC 7748), without the 0x05 prefix.
        const msg = OMEMOMessage.create({
            n: parts.counter,
            pn: parts.previousCounter,
            dh_pub: new Uint8Array(stripKeyType(parts.ephemeralKey)),
            ciphertext: new Uint8Array(parts.ciphertext),
        }) as unknown as OMEMOMessageProto;
        return OMEMOMessage.encode(msg).finish();
    },

    async computeMac(
        authKey: ArrayBuffer,
        encodedInner: Uint8Array,
        ctx: MacContext
    ): Promise<ArrayBuffer> {
        if (ctx.ad === undefined) {
            throw new Error("omemo:2 MAC requires associated data");
        }
        const macInput = concat([ctx.ad, toExactBuffer(encodedInner)]);
        const fullMac = await sign(authKey, macInput);
        return fullMac.slice(0, 16);
    },

    async verifyMac(
        authKey: ArrayBuffer,
        encodedInner: Uint8Array,
        ctx: MacContext,
        mac: ArrayBuffer
    ): Promise<void> {
        if (ctx.ad === undefined) {
            throw new Error("omemo:2 MAC requires associated data");
        }
        const macInput = concat([ctx.ad, toExactBuffer(encodedInner)]);
        await verifyMAC(macInput, authKey, mac, 16);
    },

    async frameMessage(encodedInner: Uint8Array, mac: ArrayBuffer): Promise<Uint8Array> {
        const { OMEMOAuthenticatedMessage } = await loadOMEMOMessages();
        const authMsg = OMEMOAuthenticatedMessage.create({
            mac: new Uint8Array(mac),
            message: encodedInner,
        });
        return OMEMOAuthenticatedMessage.encode(authMsg).finish();
    },

    async parseMessage(bytes: ArrayBuffer): Promise<ParsedRatchetMessage> {
        const { OMEMOMessage, OMEMOAuthenticatedMessage } = await loadOMEMOMessages();
        const authMsg = OMEMOAuthenticatedMessage.decode(new Uint8Array(bytes)) as unknown as {
            mac: Uint8Array;
            message: Uint8Array;
        };
        const encodedInner = authMsg.message;
        const message = OMEMOMessage.decode(encodedInner) as unknown as OMEMOMessageProto;
        return {
            ephemeralKey: addKeyType(toExactBuffer(message.dh_pub)),
            counter: message.n,
            previousCounter: message.pn,
            ciphertext: toExactBuffer(message.ciphertext),
            encodedInner,
            mac: toExactBuffer(authMsg.mac),
        };
    },

    async encodeKeyExchange(
        parts: KeyExchangeParts,
        framedMessage: Uint8Array
    ): Promise<Uint8Array> {
        const { OMEMOAuthenticatedMessage, OMEMOKeyExchange } = await loadOMEMOMessages();
        // ik is the 32-byte Ed25519 form of our identity key; ek is the raw 32-byte curve base key.
        const ik = await internalCrypto.curvePubKeyToEd25519PubKey(parts.ourIdentityKey.pubKey);
        // The profile interface frames messages as bytes (opaque for 0.3.0), so we
        // decode the framed OMEMOAuthenticatedMessage back into an object to nest it
        // as a structured sub-message. This keeps standalone and key-exchange-wrapped
        // messages flowing through the one bytes-based contract.
        const authMsg = OMEMOAuthenticatedMessage.decode(framedMessage);
        const kex = OMEMOKeyExchange.create({
            pk_id: parts.preKeyId ?? 0,
            spk_id: parts.signedPreKeyId,
            ik: new Uint8Array(ik),
            ek: new Uint8Array(stripKeyType(parts.baseKey)),
            message: authMsg,
        });
        return OMEMOKeyExchange.encode(kex).finish();
    },

    async parseKeyExchange(bytes: ArrayBuffer): Promise<ParsedKeyExchange> {
        const { OMEMOAuthenticatedMessage, OMEMOKeyExchange } = await loadOMEMOMessages();
        const proto = OMEMOKeyExchange.decode(
            new Uint8Array(bytes)
        ) as unknown as OMEMOKeyExchangeProto;
        const identityKeyEd = toExactBuffer(proto.ik);
        const identityKeyCurve = addKeyType(
            await internalCrypto.ed25519PubKeyToCurvePubKey(identityKeyEd)
        );
        // proto.message is already a decoded OMEMOAuthenticatedMessage; re-encode it
        // to bytes so it flows through the same ratchet-decrypt path (parseMessage)
        // that a standalone message uses.
        const framedMessage = OMEMOAuthenticatedMessage.encode(proto.message).finish();
        return {
            preKeyId: proto.pk_id,
            signedPreKeyId: proto.spk_id,
            baseKey: addKeyType(toExactBuffer(proto.ek)),
            identityKey: identityKeyCurve,
            identityKeyEd,
            message: toExactBuffer(framedMessage),
        };
    },

    wrapResult(body: Uint8Array, isKeyExchange: boolean, registrationId: number): EncryptResult {
        return {
            type: isKeyExchange ? 3 : 1,
            kex: isKeyExchange,
            body: bufferToBinaryString(body),
            registrationId,
        };
    },

    async buildAssociatedData(
        ourIdentityKey: KeyPair,
        remoteIdentityKeyEd: ArrayBuffer | undefined,
        isInitiator: boolean
    ): Promise<ArrayBuffer | undefined> {
        if (remoteIdentityKeyEd === undefined) {
            throw new Error("omemo:2 associated data requires the remote Ed25519 identity key");
        }
        const ourEd = await internalCrypto.curvePubKeyToEd25519PubKey(ourIdentityKey.pubKey);
        return isInitiator
            ? concat([ourEd, remoteIdentityKeyEd])
            : concat([remoteIdentityKeyEd, ourEd]);
    },

    async normalizeRemoteIdentityKey(wireKey: ArrayBuffer): Promise<NormalizedIdentityKey> {
        // wireKey is the 32-byte Ed25519 identity key.
        const curve = addKeyType(await internalCrypto.ed25519PubKeyToCurvePubKey(wireKey));
        return { curve, ed: wireKey };
    },

    signedPreKeySignatureData(publicKey: ArrayBuffer): ArrayBuffer {
        // omemo:2 signs the raw 32-byte Curve25519 (Montgomery) form.
        return stripKeyType(publicKey);
    },

    normalizeRemotePreKey(wireKey: ArrayBuffer): ArrayBuffer {
        // omemo:2 transfers the raw 32-byte curve form; restore the 0x05 prefix
        // to the library's internal form (no-op if already prefixed).
        return addKeyType(wireKey);
    },
};

/** Render an ArrayBuffer/Uint8Array as a binary string (one char per byte). */
function bufferToBinaryString(buf: Uint8Array): string {
    let str = "";
    for (let i = 0; i < buf.length; i++) {
        str += String.fromCharCode(buf[i]);
    }
    return str;
}

const PROFILES: Record<OMEMOVersion, ProtocolProfile> = {
    "eu.siacs.conversations.axolotl": OMEMO_0_3_0,
    "urn:xmpp:omemo:2": OMEMO_2,
};

/** Look up the protocol profile for a given OMEMO version. */
export function getProtocolProfile(version: OMEMOVersion): ProtocolProfile {
    const profile = PROFILES[version];
    if (!profile) {
        throw new Error(`Unsupported OMEMO version: ${String(version)}`);
    }
    return profile;
}

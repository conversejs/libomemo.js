import protobuf from "protobufjs";
import whisperProtoText from "../protos/WhisperTextProtocol.proto";
import pushProtoText from "../protos/push.proto";
import omemoProtoText from "../protos/OMEMO.proto";

/** OMEMO:0 */
interface ProtocolMessages {
    WhisperMessage: protobuf.Type;
    PreKeyWhisperMessage: protobuf.Type;
}

interface PushMessages {
    IncomingPushMessageSignal: protobuf.Type;
    PushMessageContent: protobuf.Type;
}

/** OMEMO:2 */
interface OMEMOMessages {
    OMEMOMessage: protobuf.Type;
    OMEMOAuthenticatedMessage: protobuf.Type;
    OMEMOKeyExchange: protobuf.Type;
}

let cachedProtocolMessages: ProtocolMessages | null = null;
let cachedPushMessages: PushMessages | null = null;
let cachedOMEMOMessages: OMEMOMessages | null = null;

/**
 * Load protobuf definitions for the Signal protocol messages.
 * Cached after first load.
 */
export async function loadProtocolMessages(): Promise<ProtocolMessages> {
    if (cachedProtocolMessages) {
        return cachedProtocolMessages;
    }

    const root = protobuf.parse(whisperProtoText).root;
    cachedProtocolMessages = {
        WhisperMessage: root.lookupType("textsecure.WhisperMessage"),
        PreKeyWhisperMessage: root.lookupType("textsecure.PreKeyWhisperMessage"),
    };
    return cachedProtocolMessages;
}

/** Load protobuf definitions for push message signals. Cached after first load. */
export async function loadPushMessages(): Promise<PushMessages> {
    if (cachedPushMessages) {
        return cachedPushMessages;
    }

    const root = protobuf.parse(pushProtoText).root;
    cachedPushMessages = {
        IncomingPushMessageSignal: root.lookupType("textsecure.IncomingPushMessageSignal"),
        PushMessageContent: root.lookupType("textsecure.PushMessageContent"),
    };
    return cachedPushMessages;
}

/**
 * Load protobuf definitions for the OMEMO 2 (urn:xmpp:omemo:2) messages.
 * Cached after first load.
 */
export async function loadOMEMOMessages(): Promise<OMEMOMessages> {
    if (cachedOMEMOMessages) {
        return cachedOMEMOMessages;
    }

    // keepCase keeps the snake_case field names (n, pn, dh_pub, pk_id, spk_id)
    // from the XEP-0384 schema instead of camelCasing them.
    const root = protobuf.parse(omemoProtoText, { keepCase: true }).root;
    cachedOMEMOMessages = {
        OMEMOMessage: root.lookupType("omemo.OMEMOMessage"),
        OMEMOAuthenticatedMessage: root.lookupType("omemo.OMEMOAuthenticatedMessage"),
        OMEMOKeyExchange: root.lookupType("omemo.OMEMOKeyExchange"),
    };
    return cachedOMEMOMessages;
}

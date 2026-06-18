import { textsecure, omemo } from "./generated/protocol.js";

/** OMEMO:0 */
interface ProtocolMessages {
    WhisperMessage: typeof textsecure.WhisperMessage;
    PreKeyWhisperMessage: typeof textsecure.PreKeyWhisperMessage;
}

interface PushMessages {
    IncomingPushMessageSignal: typeof textsecure.IncomingPushMessageSignal;
    PushMessageContent: typeof textsecure.PushMessageContent;
}

/** OMEMO:2 */
interface OMEMOMessages {
    OMEMOMessage: typeof omemo.OMEMOMessage;
    OMEMOAuthenticatedMessage: typeof omemo.OMEMOAuthenticatedMessage;
    OMEMOKeyExchange: typeof omemo.OMEMOKeyExchange;
}

/** Load codecs for the Signal protocol messages. */
export async function loadProtocolMessages(): Promise<ProtocolMessages> {
    return {
        WhisperMessage: textsecure.WhisperMessage,
        PreKeyWhisperMessage: textsecure.PreKeyWhisperMessage,
    };
}

/** Load codecs for push message signals. */
export function loadPushMessages(): PushMessages {
    return {
        IncomingPushMessageSignal: textsecure.IncomingPushMessageSignal,
        PushMessageContent: textsecure.PushMessageContent,
    };
}

/** Load codecs for the OMEMO 2 (urn:xmpp:omemo:2) messages. */
export function loadOMEMOMessages(): OMEMOMessages {
    return {
        OMEMOMessage: omemo.OMEMOMessage,
        OMEMOAuthenticatedMessage: omemo.OMEMOAuthenticatedMessage,
        OMEMOKeyExchange: omemo.OMEMOKeyExchange,
    };
}

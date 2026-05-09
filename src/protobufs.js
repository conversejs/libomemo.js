import protobuf from "protobufjs";
import whisperProtoText from "../protos/WhisperTextProtocol.proto";
import pushProtoText from "../protos/push.proto";

let cachedProtocolMessages = null;
let cachedPushMessages = null;

export async function loadProtocolMessages() {
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

export async function loadPushMessages() {
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

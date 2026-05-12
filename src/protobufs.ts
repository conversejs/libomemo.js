import protobuf from "protobufjs";
import whisperProtoText from "../protos/WhisperTextProtocol.proto";
import pushProtoText from "../protos/push.proto";

interface ProtocolMessages {
    WhisperMessage: protobuf.Type;
    PreKeyWhisperMessage: protobuf.Type;
}

interface PushMessages {
    IncomingPushMessageSignal: protobuf.Type;
    PushMessageContent: protobuf.Type;
}

let cachedProtocolMessages: ProtocolMessages | null = null;
let cachedPushMessages: PushMessages | null = null;

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

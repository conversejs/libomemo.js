/* vim: ts=4:sw=4 */
/* global protobuf */

// eslint-disable-next-line no-redeclare
var Internal = Internal || {};

Internal.protobuf = {
    async loadProtocolMessages () {
        let root;
        if (Internal.protoText && Internal.protoText['protos/WhisperTextProtocol.proto']) {
            root = protobuf.parse(Internal.protoText['protos/WhisperTextProtocol.proto']).root;
        } else {
            root = await protobuf.load('base/protos/WhisperTextProtocol.proto');
        }
        return {
            WhisperMessage: root.lookupType('textsecure.WhisperMessage'),
            PreKeyWhisperMessage: root.lookupType('textsecure.PreKeyWhisperMessage')
        };
    },

    async loadPushMessages () {
        let root;
        if (Internal.protoText && Internal.protoText['protos/push.proto']) {
            root = protobuf.parse(Internal.protoText['protos/push.proto']).root;
        } else {
            root = await protobuf.load('base/protos/push.proto');
        }
        return {
            IncomingPushMessageSignal: root.lookupType('textsecure.IncomingPushMessageSignal'),
            PushMessageContent: root.lookupType('textsecure.PushMessageContent'),
        };
    }
}

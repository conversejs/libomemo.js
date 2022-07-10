/* vim: ts=4:sw=4 */
/* global protobuf */

// eslint-disable-next-line no-redeclare
var Internal = Internal || {};

Internal.protobuf = {
    async loadProtocolMessages () {
        const root = await protobuf.load('base/protos/WhisperTextProtocol.proto');
        return {
            WhisperMessage: root.lookup('textsecure.WhisperMessage'),
            PreKeyWhisperMessage: root.lookup('textsecure.PreKeyWhisperMessage')
        };
    },

    async loadPushMessages () {
        const root = await protobuf.load('base/protos/push.proto');
        return {
            IncomingPushMessageSignal: root.lookup('textsecure.IncomingPushMessageSignal'),
            PushMessageContent: root.lookup('textsecure.PushMessageContent'),
        };
    }
}

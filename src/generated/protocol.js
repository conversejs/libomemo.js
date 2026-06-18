/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-mixed-operators, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars, default-case, jsdoc/require-param*/
import $protobuf from "protobufjs/minimal.js";

// Common aliases
const $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;
const $Object = $util.global.Object, $undefined = $util.global.undefined, $Error = $util.global.Error;

// Exported root namespace
const $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

export const textsecure = $root.textsecure = (() => {

    /**
     * Namespace textsecure.
     * @exports textsecure
     * @namespace
     */
    const textsecure = {};

    textsecure.WhisperMessage = (function() {

        /**
         * Properties of a WhisperMessage.
         * @typedef {Object} textsecure.WhisperMessage.$Properties
         * @property {Uint8Array|null} [ephemeralKey] WhisperMessage ephemeralKey
         * @property {number|null} [counter] WhisperMessage counter
         * @property {number|null} [previousCounter] WhisperMessage previousCounter
         * @property {Uint8Array|null} [ciphertext] WhisperMessage ciphertext
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of a WhisperMessage.
         * @memberof textsecure
         * @interface IWhisperMessage
         * @augments textsecure.WhisperMessage.$Properties
         * @deprecated Use textsecure.WhisperMessage.$Properties instead.
         */

        /**
         * Shape of a WhisperMessage.
         * @typedef {textsecure.WhisperMessage.$Properties} textsecure.WhisperMessage.$Shape
         */

        /**
         * Constructs a new WhisperMessage.
         * @memberof textsecure
         * @classdesc Represents a WhisperMessage.
         * @constructor
         * @param {textsecure.WhisperMessage.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const WhisperMessage = function (properties) {
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * WhisperMessage ephemeralKey.
         * @member {Uint8Array} ephemeralKey
         * @memberof textsecure.WhisperMessage
         * @instance
         */
        WhisperMessage.prototype.ephemeralKey = $util.newBuffer([]);

        /**
         * WhisperMessage counter.
         * @member {number} counter
         * @memberof textsecure.WhisperMessage
         * @instance
         */
        WhisperMessage.prototype.counter = 0;

        /**
         * WhisperMessage previousCounter.
         * @member {number} previousCounter
         * @memberof textsecure.WhisperMessage
         * @instance
         */
        WhisperMessage.prototype.previousCounter = 0;

        /**
         * WhisperMessage ciphertext.
         * @member {Uint8Array} ciphertext
         * @memberof textsecure.WhisperMessage
         * @instance
         */
        WhisperMessage.prototype.ciphertext = $util.newBuffer([]);

        /**
         * Creates a new WhisperMessage instance using the specified properties.
         * @function create
         * @memberof textsecure.WhisperMessage
         * @static
         * @param {textsecure.WhisperMessage.$Properties=} [properties] Properties to set
         * @returns {textsecure.WhisperMessage} WhisperMessage instance
         * @type {{
         *   (properties: textsecure.WhisperMessage.$Shape): textsecure.WhisperMessage & textsecure.WhisperMessage.$Shape;
         *   (properties?: textsecure.WhisperMessage.$Properties): textsecure.WhisperMessage;
         * }}
         */
        WhisperMessage.create = function(properties) {
            return new WhisperMessage(properties);
        };

        /**
         * Encodes the specified WhisperMessage message. Does not implicitly {@link textsecure.WhisperMessage.verify|verify} messages.
         * @function encode
         * @memberof textsecure.WhisperMessage
         * @static
         * @param {textsecure.WhisperMessage.$Properties} message WhisperMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        WhisperMessage.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            if (message.ephemeralKey != null && $Object.hasOwnProperty.call(message, "ephemeralKey"))
                writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.ephemeralKey);
            if (message.counter != null && $Object.hasOwnProperty.call(message, "counter"))
                writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.counter);
            if (message.previousCounter != null && $Object.hasOwnProperty.call(message, "previousCounter"))
                writer.uint32(/* id 3, wireType 0 =*/24).uint32(message.previousCounter);
            if (message.ciphertext != null && $Object.hasOwnProperty.call(message, "ciphertext"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.ciphertext);
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes a WhisperMessage message from the specified reader or buffer.
         * @function decode
         * @memberof textsecure.WhisperMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {textsecure.WhisperMessage & textsecure.WhisperMessage.$Shape} WhisperMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        WhisperMessage.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.textsecure.WhisperMessage();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 1: {
                        if (wireType !== 2)
                            break;
                        message.ephemeralKey = reader.bytes();
                        continue;
                    }
                case 2: {
                        if (wireType !== 0)
                            break;
                        message.counter = reader.uint32();
                        continue;
                    }
                case 3: {
                        if (wireType !== 0)
                            break;
                        message.previousCounter = reader.uint32();
                        continue;
                    }
                case 4: {
                        if (wireType !== 2)
                            break;
                        message.ciphertext = reader.bytes();
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            return message;
        };

        /**
         * Gets the type url for WhisperMessage
         * @function getTypeUrl
         * @memberof textsecure.WhisperMessage
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        WhisperMessage.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/textsecure.WhisperMessage";
        };

        return WhisperMessage;
    })();

    textsecure.PreKeyWhisperMessage = (function() {

        /**
         * Properties of a PreKeyWhisperMessage.
         * @typedef {Object} textsecure.PreKeyWhisperMessage.$Properties
         * @property {number|null} [registrationId] PreKeyWhisperMessage registrationId
         * @property {number|null} [preKeyId] PreKeyWhisperMessage preKeyId
         * @property {number|null} [signedPreKeyId] PreKeyWhisperMessage signedPreKeyId
         * @property {Uint8Array|null} [baseKey] PreKeyWhisperMessage baseKey
         * @property {Uint8Array|null} [identityKey] PreKeyWhisperMessage identityKey
         * @property {Uint8Array|null} [message] PreKeyWhisperMessage message
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of a PreKeyWhisperMessage.
         * @memberof textsecure
         * @interface IPreKeyWhisperMessage
         * @augments textsecure.PreKeyWhisperMessage.$Properties
         * @deprecated Use textsecure.PreKeyWhisperMessage.$Properties instead.
         */

        /**
         * Shape of a PreKeyWhisperMessage.
         * @typedef {textsecure.PreKeyWhisperMessage.$Properties} textsecure.PreKeyWhisperMessage.$Shape
         */

        /**
         * Constructs a new PreKeyWhisperMessage.
         * @memberof textsecure
         * @classdesc Represents a PreKeyWhisperMessage.
         * @constructor
         * @param {textsecure.PreKeyWhisperMessage.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const PreKeyWhisperMessage = function (properties) {
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * PreKeyWhisperMessage registrationId.
         * @member {number} registrationId
         * @memberof textsecure.PreKeyWhisperMessage
         * @instance
         */
        PreKeyWhisperMessage.prototype.registrationId = 0;

        /**
         * PreKeyWhisperMessage preKeyId.
         * @member {number} preKeyId
         * @memberof textsecure.PreKeyWhisperMessage
         * @instance
         */
        PreKeyWhisperMessage.prototype.preKeyId = 0;

        /**
         * PreKeyWhisperMessage signedPreKeyId.
         * @member {number} signedPreKeyId
         * @memberof textsecure.PreKeyWhisperMessage
         * @instance
         */
        PreKeyWhisperMessage.prototype.signedPreKeyId = 0;

        /**
         * PreKeyWhisperMessage baseKey.
         * @member {Uint8Array} baseKey
         * @memberof textsecure.PreKeyWhisperMessage
         * @instance
         */
        PreKeyWhisperMessage.prototype.baseKey = $util.newBuffer([]);

        /**
         * PreKeyWhisperMessage identityKey.
         * @member {Uint8Array} identityKey
         * @memberof textsecure.PreKeyWhisperMessage
         * @instance
         */
        PreKeyWhisperMessage.prototype.identityKey = $util.newBuffer([]);

        /**
         * PreKeyWhisperMessage message.
         * @member {Uint8Array} message
         * @memberof textsecure.PreKeyWhisperMessage
         * @instance
         */
        PreKeyWhisperMessage.prototype.message = $util.newBuffer([]);

        /**
         * Creates a new PreKeyWhisperMessage instance using the specified properties.
         * @function create
         * @memberof textsecure.PreKeyWhisperMessage
         * @static
         * @param {textsecure.PreKeyWhisperMessage.$Properties=} [properties] Properties to set
         * @returns {textsecure.PreKeyWhisperMessage} PreKeyWhisperMessage instance
         * @type {{
         *   (properties: textsecure.PreKeyWhisperMessage.$Shape): textsecure.PreKeyWhisperMessage & textsecure.PreKeyWhisperMessage.$Shape;
         *   (properties?: textsecure.PreKeyWhisperMessage.$Properties): textsecure.PreKeyWhisperMessage;
         * }}
         */
        PreKeyWhisperMessage.create = function(properties) {
            return new PreKeyWhisperMessage(properties);
        };

        /**
         * Encodes the specified PreKeyWhisperMessage message. Does not implicitly {@link textsecure.PreKeyWhisperMessage.verify|verify} messages.
         * @function encode
         * @memberof textsecure.PreKeyWhisperMessage
         * @static
         * @param {textsecure.PreKeyWhisperMessage.$Properties} message PreKeyWhisperMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        PreKeyWhisperMessage.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            if (message.preKeyId != null && $Object.hasOwnProperty.call(message, "preKeyId"))
                writer.uint32(/* id 1, wireType 0 =*/8).uint32(message.preKeyId);
            if (message.baseKey != null && $Object.hasOwnProperty.call(message, "baseKey"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.baseKey);
            if (message.identityKey != null && $Object.hasOwnProperty.call(message, "identityKey"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.identityKey);
            if (message.message != null && $Object.hasOwnProperty.call(message, "message"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.message);
            if (message.registrationId != null && $Object.hasOwnProperty.call(message, "registrationId"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint32(message.registrationId);
            if (message.signedPreKeyId != null && $Object.hasOwnProperty.call(message, "signedPreKeyId"))
                writer.uint32(/* id 6, wireType 0 =*/48).uint32(message.signedPreKeyId);
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes a PreKeyWhisperMessage message from the specified reader or buffer.
         * @function decode
         * @memberof textsecure.PreKeyWhisperMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {textsecure.PreKeyWhisperMessage & textsecure.PreKeyWhisperMessage.$Shape} PreKeyWhisperMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        PreKeyWhisperMessage.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.textsecure.PreKeyWhisperMessage();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 5: {
                        if (wireType !== 0)
                            break;
                        message.registrationId = reader.uint32();
                        continue;
                    }
                case 1: {
                        if (wireType !== 0)
                            break;
                        message.preKeyId = reader.uint32();
                        continue;
                    }
                case 6: {
                        if (wireType !== 0)
                            break;
                        message.signedPreKeyId = reader.uint32();
                        continue;
                    }
                case 2: {
                        if (wireType !== 2)
                            break;
                        message.baseKey = reader.bytes();
                        continue;
                    }
                case 3: {
                        if (wireType !== 2)
                            break;
                        message.identityKey = reader.bytes();
                        continue;
                    }
                case 4: {
                        if (wireType !== 2)
                            break;
                        message.message = reader.bytes();
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            return message;
        };

        /**
         * Gets the type url for PreKeyWhisperMessage
         * @function getTypeUrl
         * @memberof textsecure.PreKeyWhisperMessage
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        PreKeyWhisperMessage.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/textsecure.PreKeyWhisperMessage";
        };

        return PreKeyWhisperMessage;
    })();

    textsecure.KeyExchangeMessage = (function() {

        /**
         * Properties of a KeyExchangeMessage.
         * @typedef {Object} textsecure.KeyExchangeMessage.$Properties
         * @property {number|null} [id] KeyExchangeMessage id
         * @property {Uint8Array|null} [baseKey] KeyExchangeMessage baseKey
         * @property {Uint8Array|null} [ephemeralKey] KeyExchangeMessage ephemeralKey
         * @property {Uint8Array|null} [identityKey] KeyExchangeMessage identityKey
         * @property {Uint8Array|null} [baseKeySignature] KeyExchangeMessage baseKeySignature
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of a KeyExchangeMessage.
         * @memberof textsecure
         * @interface IKeyExchangeMessage
         * @augments textsecure.KeyExchangeMessage.$Properties
         * @deprecated Use textsecure.KeyExchangeMessage.$Properties instead.
         */

        /**
         * Shape of a KeyExchangeMessage.
         * @typedef {textsecure.KeyExchangeMessage.$Properties} textsecure.KeyExchangeMessage.$Shape
         */

        /**
         * Constructs a new KeyExchangeMessage.
         * @memberof textsecure
         * @classdesc Represents a KeyExchangeMessage.
         * @constructor
         * @param {textsecure.KeyExchangeMessage.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const KeyExchangeMessage = function (properties) {
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * KeyExchangeMessage id.
         * @member {number} id
         * @memberof textsecure.KeyExchangeMessage
         * @instance
         */
        KeyExchangeMessage.prototype.id = 0;

        /**
         * KeyExchangeMessage baseKey.
         * @member {Uint8Array} baseKey
         * @memberof textsecure.KeyExchangeMessage
         * @instance
         */
        KeyExchangeMessage.prototype.baseKey = $util.newBuffer([]);

        /**
         * KeyExchangeMessage ephemeralKey.
         * @member {Uint8Array} ephemeralKey
         * @memberof textsecure.KeyExchangeMessage
         * @instance
         */
        KeyExchangeMessage.prototype.ephemeralKey = $util.newBuffer([]);

        /**
         * KeyExchangeMessage identityKey.
         * @member {Uint8Array} identityKey
         * @memberof textsecure.KeyExchangeMessage
         * @instance
         */
        KeyExchangeMessage.prototype.identityKey = $util.newBuffer([]);

        /**
         * KeyExchangeMessage baseKeySignature.
         * @member {Uint8Array} baseKeySignature
         * @memberof textsecure.KeyExchangeMessage
         * @instance
         */
        KeyExchangeMessage.prototype.baseKeySignature = $util.newBuffer([]);

        /**
         * Creates a new KeyExchangeMessage instance using the specified properties.
         * @function create
         * @memberof textsecure.KeyExchangeMessage
         * @static
         * @param {textsecure.KeyExchangeMessage.$Properties=} [properties] Properties to set
         * @returns {textsecure.KeyExchangeMessage} KeyExchangeMessage instance
         * @type {{
         *   (properties: textsecure.KeyExchangeMessage.$Shape): textsecure.KeyExchangeMessage & textsecure.KeyExchangeMessage.$Shape;
         *   (properties?: textsecure.KeyExchangeMessage.$Properties): textsecure.KeyExchangeMessage;
         * }}
         */
        KeyExchangeMessage.create = function(properties) {
            return new KeyExchangeMessage(properties);
        };

        /**
         * Encodes the specified KeyExchangeMessage message. Does not implicitly {@link textsecure.KeyExchangeMessage.verify|verify} messages.
         * @function encode
         * @memberof textsecure.KeyExchangeMessage
         * @static
         * @param {textsecure.KeyExchangeMessage.$Properties} message KeyExchangeMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        KeyExchangeMessage.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            if (message.id != null && $Object.hasOwnProperty.call(message, "id"))
                writer.uint32(/* id 1, wireType 0 =*/8).uint32(message.id);
            if (message.baseKey != null && $Object.hasOwnProperty.call(message, "baseKey"))
                writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.baseKey);
            if (message.ephemeralKey != null && $Object.hasOwnProperty.call(message, "ephemeralKey"))
                writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.ephemeralKey);
            if (message.identityKey != null && $Object.hasOwnProperty.call(message, "identityKey"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.identityKey);
            if (message.baseKeySignature != null && $Object.hasOwnProperty.call(message, "baseKeySignature"))
                writer.uint32(/* id 5, wireType 2 =*/42).bytes(message.baseKeySignature);
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes a KeyExchangeMessage message from the specified reader or buffer.
         * @function decode
         * @memberof textsecure.KeyExchangeMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {textsecure.KeyExchangeMessage & textsecure.KeyExchangeMessage.$Shape} KeyExchangeMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        KeyExchangeMessage.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.textsecure.KeyExchangeMessage();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 1: {
                        if (wireType !== 0)
                            break;
                        message.id = reader.uint32();
                        continue;
                    }
                case 2: {
                        if (wireType !== 2)
                            break;
                        message.baseKey = reader.bytes();
                        continue;
                    }
                case 3: {
                        if (wireType !== 2)
                            break;
                        message.ephemeralKey = reader.bytes();
                        continue;
                    }
                case 4: {
                        if (wireType !== 2)
                            break;
                        message.identityKey = reader.bytes();
                        continue;
                    }
                case 5: {
                        if (wireType !== 2)
                            break;
                        message.baseKeySignature = reader.bytes();
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            return message;
        };

        /**
         * Gets the type url for KeyExchangeMessage
         * @function getTypeUrl
         * @memberof textsecure.KeyExchangeMessage
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        KeyExchangeMessage.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/textsecure.KeyExchangeMessage";
        };

        return KeyExchangeMessage;
    })();

    textsecure.IncomingPushMessageSignal = (function() {

        /**
         * Properties of an IncomingPushMessageSignal.
         * @typedef {Object} textsecure.IncomingPushMessageSignal.$Properties
         * @property {textsecure.IncomingPushMessageSignal.Type|null} [type] IncomingPushMessageSignal type
         * @property {string|null} [source] IncomingPushMessageSignal source
         * @property {number|null} [sourceDevice] IncomingPushMessageSignal sourceDevice
         * @property {string|null} [relay] IncomingPushMessageSignal relay
         * @property {number|null} [timestamp] IncomingPushMessageSignal timestamp
         * @property {Uint8Array|null} [message] IncomingPushMessageSignal message
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of an IncomingPushMessageSignal.
         * @memberof textsecure
         * @interface IIncomingPushMessageSignal
         * @augments textsecure.IncomingPushMessageSignal.$Properties
         * @deprecated Use textsecure.IncomingPushMessageSignal.$Properties instead.
         */

        /**
         * Shape of an IncomingPushMessageSignal.
         * @typedef {textsecure.IncomingPushMessageSignal.$Properties} textsecure.IncomingPushMessageSignal.$Shape
         */

        /**
         * Constructs a new IncomingPushMessageSignal.
         * @memberof textsecure
         * @classdesc Represents an IncomingPushMessageSignal.
         * @constructor
         * @param {textsecure.IncomingPushMessageSignal.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const IncomingPushMessageSignal = function (properties) {
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * IncomingPushMessageSignal type.
         * @member {textsecure.IncomingPushMessageSignal.Type} type
         * @memberof textsecure.IncomingPushMessageSignal
         * @instance
         */
        IncomingPushMessageSignal.prototype.type = 0;

        /**
         * IncomingPushMessageSignal source.
         * @member {string} source
         * @memberof textsecure.IncomingPushMessageSignal
         * @instance
         */
        IncomingPushMessageSignal.prototype.source = "";

        /**
         * IncomingPushMessageSignal sourceDevice.
         * @member {number} sourceDevice
         * @memberof textsecure.IncomingPushMessageSignal
         * @instance
         */
        IncomingPushMessageSignal.prototype.sourceDevice = 0;

        /**
         * IncomingPushMessageSignal relay.
         * @member {string} relay
         * @memberof textsecure.IncomingPushMessageSignal
         * @instance
         */
        IncomingPushMessageSignal.prototype.relay = "";

        /**
         * IncomingPushMessageSignal timestamp.
         * @member {number} timestamp
         * @memberof textsecure.IncomingPushMessageSignal
         * @instance
         */
        IncomingPushMessageSignal.prototype.timestamp = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

        /**
         * IncomingPushMessageSignal message.
         * @member {Uint8Array} message
         * @memberof textsecure.IncomingPushMessageSignal
         * @instance
         */
        IncomingPushMessageSignal.prototype.message = $util.newBuffer([]);

        /**
         * Creates a new IncomingPushMessageSignal instance using the specified properties.
         * @function create
         * @memberof textsecure.IncomingPushMessageSignal
         * @static
         * @param {textsecure.IncomingPushMessageSignal.$Properties=} [properties] Properties to set
         * @returns {textsecure.IncomingPushMessageSignal} IncomingPushMessageSignal instance
         * @type {{
         *   (properties: textsecure.IncomingPushMessageSignal.$Shape): textsecure.IncomingPushMessageSignal & textsecure.IncomingPushMessageSignal.$Shape;
         *   (properties?: textsecure.IncomingPushMessageSignal.$Properties): textsecure.IncomingPushMessageSignal;
         * }}
         */
        IncomingPushMessageSignal.create = function(properties) {
            return new IncomingPushMessageSignal(properties);
        };

        /**
         * Encodes the specified IncomingPushMessageSignal message. Does not implicitly {@link textsecure.IncomingPushMessageSignal.verify|verify} messages.
         * @function encode
         * @memberof textsecure.IncomingPushMessageSignal
         * @static
         * @param {textsecure.IncomingPushMessageSignal.$Properties} message IncomingPushMessageSignal message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        IncomingPushMessageSignal.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            if (message.type != null && $Object.hasOwnProperty.call(message, "type"))
                writer.uint32(/* id 1, wireType 0 =*/8).int32(message.type);
            if (message.source != null && $Object.hasOwnProperty.call(message, "source"))
                writer.uint32(/* id 2, wireType 2 =*/18).string(message.source);
            if (message.relay != null && $Object.hasOwnProperty.call(message, "relay"))
                writer.uint32(/* id 3, wireType 2 =*/26).string(message.relay);
            if (message.timestamp != null && $Object.hasOwnProperty.call(message, "timestamp"))
                writer.uint32(/* id 5, wireType 0 =*/40).uint64(message.timestamp);
            if (message.message != null && $Object.hasOwnProperty.call(message, "message"))
                writer.uint32(/* id 6, wireType 2 =*/50).bytes(message.message);
            if (message.sourceDevice != null && $Object.hasOwnProperty.call(message, "sourceDevice"))
                writer.uint32(/* id 7, wireType 0 =*/56).uint32(message.sourceDevice);
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes an IncomingPushMessageSignal message from the specified reader or buffer.
         * @function decode
         * @memberof textsecure.IncomingPushMessageSignal
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {textsecure.IncomingPushMessageSignal & textsecure.IncomingPushMessageSignal.$Shape} IncomingPushMessageSignal
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        IncomingPushMessageSignal.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.textsecure.IncomingPushMessageSignal();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 1: {
                        if (wireType !== 0)
                            break;
                        message.type = reader.int32();
                        continue;
                    }
                case 2: {
                        if (wireType !== 2)
                            break;
                        message.source = reader.string();
                        continue;
                    }
                case 7: {
                        if (wireType !== 0)
                            break;
                        message.sourceDevice = reader.uint32();
                        continue;
                    }
                case 3: {
                        if (wireType !== 2)
                            break;
                        message.relay = reader.string();
                        continue;
                    }
                case 5: {
                        if (wireType !== 0)
                            break;
                        message.timestamp = reader.uint64();
                        continue;
                    }
                case 6: {
                        if (wireType !== 2)
                            break;
                        message.message = reader.bytes();
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            return message;
        };

        /**
         * Gets the type url for IncomingPushMessageSignal
         * @function getTypeUrl
         * @memberof textsecure.IncomingPushMessageSignal
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        IncomingPushMessageSignal.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/textsecure.IncomingPushMessageSignal";
        };

        /**
         * Type enum.
         * @name textsecure.IncomingPushMessageSignal.Type
         * @enum {number}
         * @property {number} UNKNOWN=0 UNKNOWN value
         * @property {number} CIPHERTEXT=1 CIPHERTEXT value
         * @property {number} KEY_EXCHANGE=2 KEY_EXCHANGE value
         * @property {number} PREKEY_BUNDLE=3 PREKEY_BUNDLE value
         * @property {number} PLAINTEXT=4 PLAINTEXT value
         * @property {number} RECEIPT=5 RECEIPT value
         * @property {number} PREKEY_BUNDLE_DEVICE_CONTROL=6 PREKEY_BUNDLE_DEVICE_CONTROL value
         * @property {number} DEVICE_CONTROL=7 DEVICE_CONTROL value
         */
        IncomingPushMessageSignal.Type = (function() {
            const valuesById = {}, values = $Object.create(valuesById);
            values[valuesById[0] = "UNKNOWN"] = 0;
            values[valuesById[1] = "CIPHERTEXT"] = 1;
            values[valuesById[2] = "KEY_EXCHANGE"] = 2;
            values[valuesById[3] = "PREKEY_BUNDLE"] = 3;
            values[valuesById[4] = "PLAINTEXT"] = 4;
            values[valuesById[5] = "RECEIPT"] = 5;
            values[valuesById[6] = "PREKEY_BUNDLE_DEVICE_CONTROL"] = 6;
            values[valuesById[7] = "DEVICE_CONTROL"] = 7;
            return values;
        })();

        return IncomingPushMessageSignal;
    })();

    textsecure.PushMessageContent = (function() {

        /**
         * Properties of a PushMessageContent.
         * @typedef {Object} textsecure.PushMessageContent.$Properties
         * @property {string|null} [body] PushMessageContent body
         * @property {Array.<textsecure.PushMessageContent.AttachmentPointer.$Properties>|null} [attachments] PushMessageContent attachments
         * @property {textsecure.PushMessageContent.GroupContext.$Properties|null} [group] PushMessageContent group
         * @property {number|null} [flags] PushMessageContent flags
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of a PushMessageContent.
         * @memberof textsecure
         * @interface IPushMessageContent
         * @augments textsecure.PushMessageContent.$Properties
         * @deprecated Use textsecure.PushMessageContent.$Properties instead.
         */

        /**
         * Shape of a PushMessageContent.
         * @typedef {textsecure.PushMessageContent.$Properties} textsecure.PushMessageContent.$Shape
         */

        /**
         * Constructs a new PushMessageContent.
         * @memberof textsecure
         * @classdesc Represents a PushMessageContent.
         * @constructor
         * @param {textsecure.PushMessageContent.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const PushMessageContent = function (properties) {
            this.attachments = [];
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * PushMessageContent body.
         * @member {string} body
         * @memberof textsecure.PushMessageContent
         * @instance
         */
        PushMessageContent.prototype.body = "";

        /**
         * PushMessageContent attachments.
         * @member {Array.<textsecure.PushMessageContent.AttachmentPointer.$Properties>} attachments
         * @memberof textsecure.PushMessageContent
         * @instance
         */
        PushMessageContent.prototype.attachments = $util.emptyArray;

        /**
         * PushMessageContent group.
         * @member {textsecure.PushMessageContent.GroupContext.$Properties|null|undefined} group
         * @memberof textsecure.PushMessageContent
         * @instance
         */
        PushMessageContent.prototype.group = null;

        /**
         * PushMessageContent flags.
         * @member {number} flags
         * @memberof textsecure.PushMessageContent
         * @instance
         */
        PushMessageContent.prototype.flags = 0;

        /**
         * Creates a new PushMessageContent instance using the specified properties.
         * @function create
         * @memberof textsecure.PushMessageContent
         * @static
         * @param {textsecure.PushMessageContent.$Properties=} [properties] Properties to set
         * @returns {textsecure.PushMessageContent} PushMessageContent instance
         * @type {{
         *   (properties: textsecure.PushMessageContent.$Shape): textsecure.PushMessageContent & textsecure.PushMessageContent.$Shape;
         *   (properties?: textsecure.PushMessageContent.$Properties): textsecure.PushMessageContent;
         * }}
         */
        PushMessageContent.create = function(properties) {
            return new PushMessageContent(properties);
        };

        /**
         * Encodes the specified PushMessageContent message. Does not implicitly {@link textsecure.PushMessageContent.verify|verify} messages.
         * @function encode
         * @memberof textsecure.PushMessageContent
         * @static
         * @param {textsecure.PushMessageContent.$Properties} message PushMessageContent message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        PushMessageContent.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            if (message.body != null && $Object.hasOwnProperty.call(message, "body"))
                writer.uint32(/* id 1, wireType 2 =*/10).string(message.body);
            if (message.attachments != null && message.attachments.length)
                for (let i = 0; i < message.attachments.length; ++i)
                    $root.textsecure.PushMessageContent.AttachmentPointer.encode(message.attachments[i], writer.uint32(/* id 2, wireType 2 =*/18).fork(), _depth + 1).ldelim();
            if (message.group != null && $Object.hasOwnProperty.call(message, "group"))
                $root.textsecure.PushMessageContent.GroupContext.encode(message.group, writer.uint32(/* id 3, wireType 2 =*/26).fork(), _depth + 1).ldelim();
            if (message.flags != null && $Object.hasOwnProperty.call(message, "flags"))
                writer.uint32(/* id 4, wireType 0 =*/32).uint32(message.flags);
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes a PushMessageContent message from the specified reader or buffer.
         * @function decode
         * @memberof textsecure.PushMessageContent
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {textsecure.PushMessageContent & textsecure.PushMessageContent.$Shape} PushMessageContent
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        PushMessageContent.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.textsecure.PushMessageContent();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 1: {
                        if (wireType !== 2)
                            break;
                        message.body = reader.string();
                        continue;
                    }
                case 2: {
                        if (wireType !== 2)
                            break;
                        if (!(message.attachments && message.attachments.length))
                            message.attachments = [];
                        message.attachments.push($root.textsecure.PushMessageContent.AttachmentPointer.decode(reader, reader.uint32(), $undefined, _depth + 1));
                        continue;
                    }
                case 3: {
                        if (wireType !== 2)
                            break;
                        message.group = $root.textsecure.PushMessageContent.GroupContext.decode(reader, reader.uint32(), $undefined, _depth + 1, message.group);
                        continue;
                    }
                case 4: {
                        if (wireType !== 0)
                            break;
                        message.flags = reader.uint32();
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            return message;
        };

        /**
         * Gets the type url for PushMessageContent
         * @function getTypeUrl
         * @memberof textsecure.PushMessageContent
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        PushMessageContent.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/textsecure.PushMessageContent";
        };

        PushMessageContent.AttachmentPointer = (function() {

            /**
             * Properties of an AttachmentPointer.
             * @typedef {Object} textsecure.PushMessageContent.AttachmentPointer.$Properties
             * @property {number|null} [id] AttachmentPointer id
             * @property {string|null} [contentType] AttachmentPointer contentType
             * @property {Uint8Array|null} [key] AttachmentPointer key
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of an AttachmentPointer.
             * @memberof textsecure.PushMessageContent
             * @interface IAttachmentPointer
             * @augments textsecure.PushMessageContent.AttachmentPointer.$Properties
             * @deprecated Use textsecure.PushMessageContent.AttachmentPointer.$Properties instead.
             */

            /**
             * Shape of an AttachmentPointer.
             * @typedef {textsecure.PushMessageContent.AttachmentPointer.$Properties} textsecure.PushMessageContent.AttachmentPointer.$Shape
             */

            /**
             * Constructs a new AttachmentPointer.
             * @memberof textsecure.PushMessageContent
             * @classdesc Represents an AttachmentPointer.
             * @constructor
             * @param {textsecure.PushMessageContent.AttachmentPointer.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const AttachmentPointer = function (properties) {
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * AttachmentPointer id.
             * @member {number} id
             * @memberof textsecure.PushMessageContent.AttachmentPointer
             * @instance
             */
            AttachmentPointer.prototype.id = $util.Long ? $util.Long.fromBits(0,0,true) : 0;

            /**
             * AttachmentPointer contentType.
             * @member {string} contentType
             * @memberof textsecure.PushMessageContent.AttachmentPointer
             * @instance
             */
            AttachmentPointer.prototype.contentType = "";

            /**
             * AttachmentPointer key.
             * @member {Uint8Array} key
             * @memberof textsecure.PushMessageContent.AttachmentPointer
             * @instance
             */
            AttachmentPointer.prototype.key = $util.newBuffer([]);

            /**
             * Creates a new AttachmentPointer instance using the specified properties.
             * @function create
             * @memberof textsecure.PushMessageContent.AttachmentPointer
             * @static
             * @param {textsecure.PushMessageContent.AttachmentPointer.$Properties=} [properties] Properties to set
             * @returns {textsecure.PushMessageContent.AttachmentPointer} AttachmentPointer instance
             * @type {{
             *   (properties: textsecure.PushMessageContent.AttachmentPointer.$Shape): textsecure.PushMessageContent.AttachmentPointer & textsecure.PushMessageContent.AttachmentPointer.$Shape;
             *   (properties?: textsecure.PushMessageContent.AttachmentPointer.$Properties): textsecure.PushMessageContent.AttachmentPointer;
             * }}
             */
            AttachmentPointer.create = function(properties) {
                return new AttachmentPointer(properties);
            };

            /**
             * Encodes the specified AttachmentPointer message. Does not implicitly {@link textsecure.PushMessageContent.AttachmentPointer.verify|verify} messages.
             * @function encode
             * @memberof textsecure.PushMessageContent.AttachmentPointer
             * @static
             * @param {textsecure.PushMessageContent.AttachmentPointer.$Properties} message AttachmentPointer message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            AttachmentPointer.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.id != null && $Object.hasOwnProperty.call(message, "id"))
                    writer.uint32(/* id 1, wireType 1 =*/9).fixed64(message.id);
                if (message.contentType != null && $Object.hasOwnProperty.call(message, "contentType"))
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.contentType);
                if (message.key != null && $Object.hasOwnProperty.call(message, "key"))
                    writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.key);
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Decodes an AttachmentPointer message from the specified reader or buffer.
             * @function decode
             * @memberof textsecure.PushMessageContent.AttachmentPointer
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {textsecure.PushMessageContent.AttachmentPointer & textsecure.PushMessageContent.AttachmentPointer.$Shape} AttachmentPointer
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            AttachmentPointer.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.textsecure.PushMessageContent.AttachmentPointer();
                while (reader.pos < end) {
                    let start = reader.pos;
                    let tag = reader.tag();
                    if (tag === _end) {
                        _end = $undefined;
                        break;
                    }
                    let wireType = tag & 7;
                    switch (tag >>>= 3) {
                    case 1: {
                            if (wireType !== 1)
                                break;
                            message.id = reader.fixed64();
                            continue;
                        }
                    case 2: {
                            if (wireType !== 2)
                                break;
                            message.contentType = reader.string();
                            continue;
                        }
                    case 3: {
                            if (wireType !== 2)
                                break;
                            message.key = reader.bytes();
                            continue;
                        }
                    }
                    reader.skipType(wireType, _depth, tag);
                    if (!reader.discardUnknown) {
                        $util.makeProp(message, "$unknowns", false);
                        (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                    }
                }
                if (_end !== $undefined)
                    throw $Error("missing end group");
                return message;
            };

            /**
             * Gets the type url for AttachmentPointer
             * @function getTypeUrl
             * @memberof textsecure.PushMessageContent.AttachmentPointer
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            AttachmentPointer.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/textsecure.PushMessageContent.AttachmentPointer";
            };

            return AttachmentPointer;
        })();

        PushMessageContent.GroupContext = (function() {

            /**
             * Properties of a GroupContext.
             * @typedef {Object} textsecure.PushMessageContent.GroupContext.$Properties
             * @property {Uint8Array|null} [id] GroupContext id
             * @property {textsecure.PushMessageContent.GroupContext.Type|null} [type] GroupContext type
             * @property {string|null} [name] GroupContext name
             * @property {Array.<string>|null} [members] GroupContext members
             * @property {textsecure.PushMessageContent.AttachmentPointer.$Properties|null} [avatar] GroupContext avatar
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */

            /**
             * Properties of a GroupContext.
             * @memberof textsecure.PushMessageContent
             * @interface IGroupContext
             * @augments textsecure.PushMessageContent.GroupContext.$Properties
             * @deprecated Use textsecure.PushMessageContent.GroupContext.$Properties instead.
             */

            /**
             * Shape of a GroupContext.
             * @typedef {textsecure.PushMessageContent.GroupContext.$Properties} textsecure.PushMessageContent.GroupContext.$Shape
             */

            /**
             * Constructs a new GroupContext.
             * @memberof textsecure.PushMessageContent
             * @classdesc Represents a GroupContext.
             * @constructor
             * @param {textsecure.PushMessageContent.GroupContext.$Properties=} [properties] Properties to set
             * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
             */
            const GroupContext = function (properties) {
                this.members = [];
                if (properties)
                    for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                        if (properties[keys[i]] != null && keys[i] !== "__proto__")
                            this[keys[i]] = properties[keys[i]];
            };

            /**
             * GroupContext id.
             * @member {Uint8Array} id
             * @memberof textsecure.PushMessageContent.GroupContext
             * @instance
             */
            GroupContext.prototype.id = $util.newBuffer([]);

            /**
             * GroupContext type.
             * @member {textsecure.PushMessageContent.GroupContext.Type} type
             * @memberof textsecure.PushMessageContent.GroupContext
             * @instance
             */
            GroupContext.prototype.type = 0;

            /**
             * GroupContext name.
             * @member {string} name
             * @memberof textsecure.PushMessageContent.GroupContext
             * @instance
             */
            GroupContext.prototype.name = "";

            /**
             * GroupContext members.
             * @member {Array.<string>} members
             * @memberof textsecure.PushMessageContent.GroupContext
             * @instance
             */
            GroupContext.prototype.members = $util.emptyArray;

            /**
             * GroupContext avatar.
             * @member {textsecure.PushMessageContent.AttachmentPointer.$Properties|null|undefined} avatar
             * @memberof textsecure.PushMessageContent.GroupContext
             * @instance
             */
            GroupContext.prototype.avatar = null;

            /**
             * Creates a new GroupContext instance using the specified properties.
             * @function create
             * @memberof textsecure.PushMessageContent.GroupContext
             * @static
             * @param {textsecure.PushMessageContent.GroupContext.$Properties=} [properties] Properties to set
             * @returns {textsecure.PushMessageContent.GroupContext} GroupContext instance
             * @type {{
             *   (properties: textsecure.PushMessageContent.GroupContext.$Shape): textsecure.PushMessageContent.GroupContext & textsecure.PushMessageContent.GroupContext.$Shape;
             *   (properties?: textsecure.PushMessageContent.GroupContext.$Properties): textsecure.PushMessageContent.GroupContext;
             * }}
             */
            GroupContext.create = function(properties) {
                return new GroupContext(properties);
            };

            /**
             * Encodes the specified GroupContext message. Does not implicitly {@link textsecure.PushMessageContent.GroupContext.verify|verify} messages.
             * @function encode
             * @memberof textsecure.PushMessageContent.GroupContext
             * @static
             * @param {textsecure.PushMessageContent.GroupContext.$Properties} message GroupContext message or plain object to encode
             * @param {$protobuf.Writer} [writer] Writer to encode to
             * @returns {$protobuf.Writer} Writer
             */
            GroupContext.encode = function (message, writer, _depth) {
                if (!writer)
                    writer = $Writer.create();
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $util.recursionLimit)
                    throw $Error("max depth exceeded");
                if (message.id != null && $Object.hasOwnProperty.call(message, "id"))
                    writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.id);
                if (message.type != null && $Object.hasOwnProperty.call(message, "type"))
                    writer.uint32(/* id 2, wireType 0 =*/16).int32(message.type);
                if (message.name != null && $Object.hasOwnProperty.call(message, "name"))
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.name);
                if (message.members != null && message.members.length)
                    for (let i = 0; i < message.members.length; ++i)
                        writer.uint32(/* id 4, wireType 2 =*/34).string(message.members[i]);
                if (message.avatar != null && $Object.hasOwnProperty.call(message, "avatar"))
                    $root.textsecure.PushMessageContent.AttachmentPointer.encode(message.avatar, writer.uint32(/* id 5, wireType 2 =*/42).fork(), _depth + 1).ldelim();
                if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                    for (let i = 0; i < message.$unknowns.length; ++i)
                        writer.raw(message.$unknowns[i]);
                return writer;
            };

            /**
             * Decodes a GroupContext message from the specified reader or buffer.
             * @function decode
             * @memberof textsecure.PushMessageContent.GroupContext
             * @static
             * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
             * @param {number} [length] Message length if known beforehand
             * @returns {textsecure.PushMessageContent.GroupContext & textsecure.PushMessageContent.GroupContext.$Shape} GroupContext
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            GroupContext.decode = function (reader, length, _end, _depth, _target) {
                if (!(reader instanceof $Reader))
                    reader = $Reader.create(reader);
                if (_depth === $undefined)
                    _depth = 0;
                if (_depth > $Reader.recursionLimit)
                    throw $Error("max depth exceeded");
                let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.textsecure.PushMessageContent.GroupContext();
                while (reader.pos < end) {
                    let start = reader.pos;
                    let tag = reader.tag();
                    if (tag === _end) {
                        _end = $undefined;
                        break;
                    }
                    let wireType = tag & 7;
                    switch (tag >>>= 3) {
                    case 1: {
                            if (wireType !== 2)
                                break;
                            message.id = reader.bytes();
                            continue;
                        }
                    case 2: {
                            if (wireType !== 0)
                                break;
                            message.type = reader.int32();
                            continue;
                        }
                    case 3: {
                            if (wireType !== 2)
                                break;
                            message.name = reader.string();
                            continue;
                        }
                    case 4: {
                            if (wireType !== 2)
                                break;
                            if (!(message.members && message.members.length))
                                message.members = [];
                            message.members.push(reader.string());
                            continue;
                        }
                    case 5: {
                            if (wireType !== 2)
                                break;
                            message.avatar = $root.textsecure.PushMessageContent.AttachmentPointer.decode(reader, reader.uint32(), $undefined, _depth + 1, message.avatar);
                            continue;
                        }
                    }
                    reader.skipType(wireType, _depth, tag);
                    if (!reader.discardUnknown) {
                        $util.makeProp(message, "$unknowns", false);
                        (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                    }
                }
                if (_end !== $undefined)
                    throw $Error("missing end group");
                return message;
            };

            /**
             * Gets the type url for GroupContext
             * @function getTypeUrl
             * @memberof textsecure.PushMessageContent.GroupContext
             * @static
             * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns {string} The type url
             */
            GroupContext.getTypeUrl = function(prefix) {
                if (prefix === $undefined)
                    prefix = "type.googleapis.com";
                return prefix + "/textsecure.PushMessageContent.GroupContext";
            };

            /**
             * Type enum.
             * @name textsecure.PushMessageContent.GroupContext.Type
             * @enum {number}
             * @property {number} UNKNOWN=0 UNKNOWN value
             * @property {number} UPDATE=1 UPDATE value
             * @property {number} DELIVER=2 DELIVER value
             * @property {number} QUIT=3 QUIT value
             */
            GroupContext.Type = (function() {
                const valuesById = {}, values = $Object.create(valuesById);
                values[valuesById[0] = "UNKNOWN"] = 0;
                values[valuesById[1] = "UPDATE"] = 1;
                values[valuesById[2] = "DELIVER"] = 2;
                values[valuesById[3] = "QUIT"] = 3;
                return values;
            })();

            return GroupContext;
        })();

        /**
         * Flags enum.
         * @name textsecure.PushMessageContent.Flags
         * @enum {number}
         * @property {number} END_SESSION=1 END_SESSION value
         */
        PushMessageContent.Flags = (function() {
            const valuesById = {}, values = $Object.create(valuesById);
            values[valuesById[1] = "END_SESSION"] = 1;
            return values;
        })();

        return PushMessageContent;
    })();

    return textsecure;
})();

export const omemo = $root.omemo = (() => {

    /**
     * Namespace omemo.
     * @exports omemo
     * @namespace
     */
    const omemo = {};

    omemo.OMEMOMessage = (function() {

        /**
         * Properties of a OMEMOMessage.
         * @typedef {Object} omemo.OMEMOMessage.$Properties
         * @property {number} n OMEMOMessage n
         * @property {number} pn OMEMOMessage pn
         * @property {Uint8Array} dh_pub OMEMOMessage dh_pub
         * @property {Uint8Array|null} [ciphertext] OMEMOMessage ciphertext
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of a OMEMOMessage.
         * @memberof omemo
         * @interface IOMEMOMessage
         * @augments omemo.OMEMOMessage.$Properties
         * @deprecated Use omemo.OMEMOMessage.$Properties instead.
         */

        /**
         * Shape of a OMEMOMessage.
         * @typedef {omemo.OMEMOMessage.$Properties} omemo.OMEMOMessage.$Shape
         */

        /**
         * Constructs a new OMEMOMessage.
         * @memberof omemo
         * @classdesc Represents a OMEMOMessage.
         * @constructor
         * @param {omemo.OMEMOMessage.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const OMEMOMessage = function (properties) {
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * OMEMOMessage n.
         * @member {number} n
         * @memberof omemo.OMEMOMessage
         * @instance
         */
        OMEMOMessage.prototype.n = 0;

        /**
         * OMEMOMessage pn.
         * @member {number} pn
         * @memberof omemo.OMEMOMessage
         * @instance
         */
        OMEMOMessage.prototype.pn = 0;

        /**
         * OMEMOMessage dh_pub.
         * @member {Uint8Array} dh_pub
         * @memberof omemo.OMEMOMessage
         * @instance
         */
        OMEMOMessage.prototype.dh_pub = $util.newBuffer([]);

        /**
         * OMEMOMessage ciphertext.
         * @member {Uint8Array} ciphertext
         * @memberof omemo.OMEMOMessage
         * @instance
         */
        OMEMOMessage.prototype.ciphertext = $util.newBuffer([]);

        /**
         * Creates a new OMEMOMessage instance using the specified properties.
         * @function create
         * @memberof omemo.OMEMOMessage
         * @static
         * @param {omemo.OMEMOMessage.$Properties=} [properties] Properties to set
         * @returns {omemo.OMEMOMessage} OMEMOMessage instance
         * @type {{
         *   (properties: omemo.OMEMOMessage.$Shape): omemo.OMEMOMessage & omemo.OMEMOMessage.$Shape;
         *   (properties?: omemo.OMEMOMessage.$Properties): omemo.OMEMOMessage;
         * }}
         */
        OMEMOMessage.create = function(properties) {
            return new OMEMOMessage(properties);
        };

        /**
         * Encodes the specified OMEMOMessage message. Does not implicitly {@link omemo.OMEMOMessage.verify|verify} messages.
         * @function encode
         * @memberof omemo.OMEMOMessage
         * @static
         * @param {omemo.OMEMOMessage.$Properties} message OMEMOMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        OMEMOMessage.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            writer.uint32(/* id 1, wireType 0 =*/8).uint32(message.n);
            writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.pn);
            writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.dh_pub);
            if (message.ciphertext != null && $Object.hasOwnProperty.call(message, "ciphertext"))
                writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.ciphertext);
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes a OMEMOMessage message from the specified reader or buffer.
         * @function decode
         * @memberof omemo.OMEMOMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {omemo.OMEMOMessage & omemo.OMEMOMessage.$Shape} OMEMOMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        OMEMOMessage.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.omemo.OMEMOMessage();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 1: {
                        if (wireType !== 0)
                            break;
                        message.n = reader.uint32();
                        continue;
                    }
                case 2: {
                        if (wireType !== 0)
                            break;
                        message.pn = reader.uint32();
                        continue;
                    }
                case 3: {
                        if (wireType !== 2)
                            break;
                        message.dh_pub = reader.bytes();
                        continue;
                    }
                case 4: {
                        if (wireType !== 2)
                            break;
                        message.ciphertext = reader.bytes();
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            if (!$Object.hasOwnProperty.call(message, "n"))
                throw $util.ProtocolError("missing required 'n'", { instance: message });
            if (!$Object.hasOwnProperty.call(message, "pn"))
                throw $util.ProtocolError("missing required 'pn'", { instance: message });
            if (!$Object.hasOwnProperty.call(message, "dh_pub"))
                throw $util.ProtocolError("missing required 'dh_pub'", { instance: message });
            return message;
        };

        /**
         * Gets the type url for OMEMOMessage
         * @function getTypeUrl
         * @memberof omemo.OMEMOMessage
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        OMEMOMessage.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/omemo.OMEMOMessage";
        };

        return OMEMOMessage;
    })();

    omemo.OMEMOAuthenticatedMessage = (function() {

        /**
         * Properties of a OMEMOAuthenticatedMessage.
         * @typedef {Object} omemo.OMEMOAuthenticatedMessage.$Properties
         * @property {Uint8Array} mac OMEMOAuthenticatedMessage mac
         * @property {Uint8Array} message OMEMOAuthenticatedMessage message
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of a OMEMOAuthenticatedMessage.
         * @memberof omemo
         * @interface IOMEMOAuthenticatedMessage
         * @augments omemo.OMEMOAuthenticatedMessage.$Properties
         * @deprecated Use omemo.OMEMOAuthenticatedMessage.$Properties instead.
         */

        /**
         * Shape of a OMEMOAuthenticatedMessage.
         * @typedef {omemo.OMEMOAuthenticatedMessage.$Properties} omemo.OMEMOAuthenticatedMessage.$Shape
         */

        /**
         * Constructs a new OMEMOAuthenticatedMessage.
         * @memberof omemo
         * @classdesc Represents a OMEMOAuthenticatedMessage.
         * @constructor
         * @param {omemo.OMEMOAuthenticatedMessage.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const OMEMOAuthenticatedMessage = function (properties) {
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * OMEMOAuthenticatedMessage mac.
         * @member {Uint8Array} mac
         * @memberof omemo.OMEMOAuthenticatedMessage
         * @instance
         */
        OMEMOAuthenticatedMessage.prototype.mac = $util.newBuffer([]);

        /**
         * OMEMOAuthenticatedMessage message.
         * @member {Uint8Array} message
         * @memberof omemo.OMEMOAuthenticatedMessage
         * @instance
         */
        OMEMOAuthenticatedMessage.prototype.message = $util.newBuffer([]);

        /**
         * Creates a new OMEMOAuthenticatedMessage instance using the specified properties.
         * @function create
         * @memberof omemo.OMEMOAuthenticatedMessage
         * @static
         * @param {omemo.OMEMOAuthenticatedMessage.$Properties=} [properties] Properties to set
         * @returns {omemo.OMEMOAuthenticatedMessage} OMEMOAuthenticatedMessage instance
         * @type {{
         *   (properties: omemo.OMEMOAuthenticatedMessage.$Shape): omemo.OMEMOAuthenticatedMessage & omemo.OMEMOAuthenticatedMessage.$Shape;
         *   (properties?: omemo.OMEMOAuthenticatedMessage.$Properties): omemo.OMEMOAuthenticatedMessage;
         * }}
         */
        OMEMOAuthenticatedMessage.create = function(properties) {
            return new OMEMOAuthenticatedMessage(properties);
        };

        /**
         * Encodes the specified OMEMOAuthenticatedMessage message. Does not implicitly {@link omemo.OMEMOAuthenticatedMessage.verify|verify} messages.
         * @function encode
         * @memberof omemo.OMEMOAuthenticatedMessage
         * @static
         * @param {omemo.OMEMOAuthenticatedMessage.$Properties} message OMEMOAuthenticatedMessage message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        OMEMOAuthenticatedMessage.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.mac);
            writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.message);
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes a OMEMOAuthenticatedMessage message from the specified reader or buffer.
         * @function decode
         * @memberof omemo.OMEMOAuthenticatedMessage
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {omemo.OMEMOAuthenticatedMessage & omemo.OMEMOAuthenticatedMessage.$Shape} OMEMOAuthenticatedMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        OMEMOAuthenticatedMessage.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.omemo.OMEMOAuthenticatedMessage();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 1: {
                        if (wireType !== 2)
                            break;
                        message.mac = reader.bytes();
                        continue;
                    }
                case 2: {
                        if (wireType !== 2)
                            break;
                        message.message = reader.bytes();
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            if (!$Object.hasOwnProperty.call(message, "mac"))
                throw $util.ProtocolError("missing required 'mac'", { instance: message });
            if (!$Object.hasOwnProperty.call(message, "message"))
                throw $util.ProtocolError("missing required 'message'", { instance: message });
            return message;
        };

        /**
         * Gets the type url for OMEMOAuthenticatedMessage
         * @function getTypeUrl
         * @memberof omemo.OMEMOAuthenticatedMessage
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        OMEMOAuthenticatedMessage.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/omemo.OMEMOAuthenticatedMessage";
        };

        return OMEMOAuthenticatedMessage;
    })();

    omemo.OMEMOKeyExchange = (function() {

        /**
         * Properties of a OMEMOKeyExchange.
         * @typedef {Object} omemo.OMEMOKeyExchange.$Properties
         * @property {number} pk_id OMEMOKeyExchange pk_id
         * @property {number} spk_id OMEMOKeyExchange spk_id
         * @property {Uint8Array} ik OMEMOKeyExchange ik
         * @property {Uint8Array} ek OMEMOKeyExchange ek
         * @property {omemo.OMEMOAuthenticatedMessage.$Properties} message OMEMOKeyExchange message
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */

        /**
         * Properties of a OMEMOKeyExchange.
         * @memberof omemo
         * @interface IOMEMOKeyExchange
         * @augments omemo.OMEMOKeyExchange.$Properties
         * @deprecated Use omemo.OMEMOKeyExchange.$Properties instead.
         */

        /**
         * Shape of a OMEMOKeyExchange.
         * @typedef {omemo.OMEMOKeyExchange.$Properties} omemo.OMEMOKeyExchange.$Shape
         */

        /**
         * Constructs a new OMEMOKeyExchange.
         * @memberof omemo
         * @classdesc Represents a OMEMOKeyExchange.
         * @constructor
         * @param {omemo.OMEMOKeyExchange.$Properties=} [properties] Properties to set
         * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
         */
        const OMEMOKeyExchange = function (properties) {
            if (properties)
                for (let keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                    if (properties[keys[i]] != null && keys[i] !== "__proto__")
                        this[keys[i]] = properties[keys[i]];
        };

        /**
         * OMEMOKeyExchange pk_id.
         * @member {number} pk_id
         * @memberof omemo.OMEMOKeyExchange
         * @instance
         */
        OMEMOKeyExchange.prototype.pk_id = 0;

        /**
         * OMEMOKeyExchange spk_id.
         * @member {number} spk_id
         * @memberof omemo.OMEMOKeyExchange
         * @instance
         */
        OMEMOKeyExchange.prototype.spk_id = 0;

        /**
         * OMEMOKeyExchange ik.
         * @member {Uint8Array} ik
         * @memberof omemo.OMEMOKeyExchange
         * @instance
         */
        OMEMOKeyExchange.prototype.ik = $util.newBuffer([]);

        /**
         * OMEMOKeyExchange ek.
         * @member {Uint8Array} ek
         * @memberof omemo.OMEMOKeyExchange
         * @instance
         */
        OMEMOKeyExchange.prototype.ek = $util.newBuffer([]);

        /**
         * OMEMOKeyExchange message.
         * @member {omemo.OMEMOAuthenticatedMessage.$Properties} message
         * @memberof omemo.OMEMOKeyExchange
         * @instance
         */
        OMEMOKeyExchange.prototype.message = null;

        /**
         * Creates a new OMEMOKeyExchange instance using the specified properties.
         * @function create
         * @memberof omemo.OMEMOKeyExchange
         * @static
         * @param {omemo.OMEMOKeyExchange.$Properties=} [properties] Properties to set
         * @returns {omemo.OMEMOKeyExchange} OMEMOKeyExchange instance
         * @type {{
         *   (properties: omemo.OMEMOKeyExchange.$Shape): omemo.OMEMOKeyExchange & omemo.OMEMOKeyExchange.$Shape;
         *   (properties?: omemo.OMEMOKeyExchange.$Properties): omemo.OMEMOKeyExchange;
         * }}
         */
        OMEMOKeyExchange.create = function(properties) {
            return new OMEMOKeyExchange(properties);
        };

        /**
         * Encodes the specified OMEMOKeyExchange message. Does not implicitly {@link omemo.OMEMOKeyExchange.verify|verify} messages.
         * @function encode
         * @memberof omemo.OMEMOKeyExchange
         * @static
         * @param {omemo.OMEMOKeyExchange.$Properties} message OMEMOKeyExchange message or plain object to encode
         * @param {$protobuf.Writer} [writer] Writer to encode to
         * @returns {$protobuf.Writer} Writer
         */
        OMEMOKeyExchange.encode = function (message, writer, _depth) {
            if (!writer)
                writer = $Writer.create();
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $util.recursionLimit)
                throw $Error("max depth exceeded");
            writer.uint32(/* id 1, wireType 0 =*/8).uint32(message.pk_id);
            writer.uint32(/* id 2, wireType 0 =*/16).uint32(message.spk_id);
            writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.ik);
            writer.uint32(/* id 4, wireType 2 =*/34).bytes(message.ek);
            $root.omemo.OMEMOAuthenticatedMessage.encode(message.message, writer.uint32(/* id 5, wireType 2 =*/42).fork(), _depth + 1).ldelim();
            if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                for (let i = 0; i < message.$unknowns.length; ++i)
                    writer.raw(message.$unknowns[i]);
            return writer;
        };

        /**
         * Decodes a OMEMOKeyExchange message from the specified reader or buffer.
         * @function decode
         * @memberof omemo.OMEMOKeyExchange
         * @static
         * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
         * @param {number} [length] Message length if known beforehand
         * @returns {omemo.OMEMOKeyExchange & omemo.OMEMOKeyExchange.$Shape} OMEMOKeyExchange
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        OMEMOKeyExchange.decode = function (reader, length, _end, _depth, _target) {
            if (!(reader instanceof $Reader))
                reader = $Reader.create(reader);
            if (_depth === $undefined)
                _depth = 0;
            if (_depth > $Reader.recursionLimit)
                throw $Error("max depth exceeded");
            let end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.omemo.OMEMOKeyExchange();
            while (reader.pos < end) {
                let start = reader.pos;
                let tag = reader.tag();
                if (tag === _end) {
                    _end = $undefined;
                    break;
                }
                let wireType = tag & 7;
                switch (tag >>>= 3) {
                case 1: {
                        if (wireType !== 0)
                            break;
                        message.pk_id = reader.uint32();
                        continue;
                    }
                case 2: {
                        if (wireType !== 0)
                            break;
                        message.spk_id = reader.uint32();
                        continue;
                    }
                case 3: {
                        if (wireType !== 2)
                            break;
                        message.ik = reader.bytes();
                        continue;
                    }
                case 4: {
                        if (wireType !== 2)
                            break;
                        message.ek = reader.bytes();
                        continue;
                    }
                case 5: {
                        if (wireType !== 2)
                            break;
                        message.message = $root.omemo.OMEMOAuthenticatedMessage.decode(reader, reader.uint32(), $undefined, _depth + 1, message.message);
                        continue;
                    }
                }
                reader.skipType(wireType, _depth, tag);
                if (!reader.discardUnknown) {
                    $util.makeProp(message, "$unknowns", false);
                    (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                }
            }
            if (_end !== $undefined)
                throw $Error("missing end group");
            if (!$Object.hasOwnProperty.call(message, "pk_id"))
                throw $util.ProtocolError("missing required 'pk_id'", { instance: message });
            if (!$Object.hasOwnProperty.call(message, "spk_id"))
                throw $util.ProtocolError("missing required 'spk_id'", { instance: message });
            if (!$Object.hasOwnProperty.call(message, "ik"))
                throw $util.ProtocolError("missing required 'ik'", { instance: message });
            if (!$Object.hasOwnProperty.call(message, "ek"))
                throw $util.ProtocolError("missing required 'ek'", { instance: message });
            if (!$Object.hasOwnProperty.call(message, "message"))
                throw $util.ProtocolError("missing required 'message'", { instance: message });
            return message;
        };

        /**
         * Gets the type url for OMEMOKeyExchange
         * @function getTypeUrl
         * @memberof omemo.OMEMOKeyExchange
         * @static
         * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns {string} The type url
         */
        OMEMOKeyExchange.getTypeUrl = function(prefix) {
            if (prefix === $undefined)
                prefix = "type.googleapis.com";
            return prefix + "/omemo.OMEMOKeyExchange";
        };

        return OMEMOKeyExchange;
    })();

    return omemo;
})();

export {
  $root as default
};

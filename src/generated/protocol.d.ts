import * as $protobuf from "protobufjs";

/** Namespace textsecure. */
export namespace textsecure {

    /**
     * Properties of a WhisperMessage.
     * @deprecated Use textsecure.WhisperMessage.$Properties instead.
     */
    interface IWhisperMessage extends textsecure.WhisperMessage.$Properties {
    }

    /** Represents a WhisperMessage. */
    class WhisperMessage {

        /**
         * Constructs a new WhisperMessage.
         * @param [properties] Properties to set
         */
        constructor(properties?: textsecure.WhisperMessage.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** WhisperMessage ephemeralKey. */
        ephemeralKey: Uint8Array;

        /** WhisperMessage counter. */
        counter: number;

        /** WhisperMessage previousCounter. */
        previousCounter: number;

        /** WhisperMessage ciphertext. */
        ciphertext: Uint8Array;

        /**
         * Creates a new WhisperMessage instance using the specified properties.
         * @param [properties] Properties to set
         * @returns WhisperMessage instance
         */
        static create(properties: textsecure.WhisperMessage.$Shape): textsecure.WhisperMessage & textsecure.WhisperMessage.$Shape;
        static create(properties?: textsecure.WhisperMessage.$Properties): textsecure.WhisperMessage;

        /**
         * Encodes the specified WhisperMessage message. Does not implicitly {@link textsecure.WhisperMessage.verify|verify} messages.
         * @param message WhisperMessage message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: textsecure.WhisperMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a WhisperMessage message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {textsecure.WhisperMessage & textsecure.WhisperMessage.$Shape} WhisperMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): textsecure.WhisperMessage & textsecure.WhisperMessage.$Shape;

        /**
         * Gets the type url for WhisperMessage
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace WhisperMessage {

        /** Properties of a WhisperMessage. */
        interface $Properties {

            /** WhisperMessage ephemeralKey */
            ephemeralKey?: (Uint8Array|null);

            /** WhisperMessage counter */
            counter?: (number|null);

            /** WhisperMessage previousCounter */
            previousCounter?: (number|null);

            /** WhisperMessage ciphertext */
            ciphertext?: (Uint8Array|null);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of a WhisperMessage. */
        type $Shape = textsecure.WhisperMessage.$Properties;
    }

    /**
     * Properties of a PreKeyWhisperMessage.
     * @deprecated Use textsecure.PreKeyWhisperMessage.$Properties instead.
     */
    interface IPreKeyWhisperMessage extends textsecure.PreKeyWhisperMessage.$Properties {
    }

    /** Represents a PreKeyWhisperMessage. */
    class PreKeyWhisperMessage {

        /**
         * Constructs a new PreKeyWhisperMessage.
         * @param [properties] Properties to set
         */
        constructor(properties?: textsecure.PreKeyWhisperMessage.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** PreKeyWhisperMessage registrationId. */
        registrationId: number;

        /** PreKeyWhisperMessage preKeyId. */
        preKeyId: number;

        /** PreKeyWhisperMessage signedPreKeyId. */
        signedPreKeyId: number;

        /** PreKeyWhisperMessage baseKey. */
        baseKey: Uint8Array;

        /** PreKeyWhisperMessage identityKey. */
        identityKey: Uint8Array;

        /** PreKeyWhisperMessage message. */
        message: Uint8Array;

        /**
         * Creates a new PreKeyWhisperMessage instance using the specified properties.
         * @param [properties] Properties to set
         * @returns PreKeyWhisperMessage instance
         */
        static create(properties: textsecure.PreKeyWhisperMessage.$Shape): textsecure.PreKeyWhisperMessage & textsecure.PreKeyWhisperMessage.$Shape;
        static create(properties?: textsecure.PreKeyWhisperMessage.$Properties): textsecure.PreKeyWhisperMessage;

        /**
         * Encodes the specified PreKeyWhisperMessage message. Does not implicitly {@link textsecure.PreKeyWhisperMessage.verify|verify} messages.
         * @param message PreKeyWhisperMessage message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: textsecure.PreKeyWhisperMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a PreKeyWhisperMessage message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {textsecure.PreKeyWhisperMessage & textsecure.PreKeyWhisperMessage.$Shape} PreKeyWhisperMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): textsecure.PreKeyWhisperMessage & textsecure.PreKeyWhisperMessage.$Shape;

        /**
         * Gets the type url for PreKeyWhisperMessage
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace PreKeyWhisperMessage {

        /** Properties of a PreKeyWhisperMessage. */
        interface $Properties {

            /** PreKeyWhisperMessage registrationId */
            registrationId?: (number|null);

            /** PreKeyWhisperMessage preKeyId */
            preKeyId?: (number|null);

            /** PreKeyWhisperMessage signedPreKeyId */
            signedPreKeyId?: (number|null);

            /** PreKeyWhisperMessage baseKey */
            baseKey?: (Uint8Array|null);

            /** PreKeyWhisperMessage identityKey */
            identityKey?: (Uint8Array|null);

            /** PreKeyWhisperMessage message */
            message?: (Uint8Array|null);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of a PreKeyWhisperMessage. */
        type $Shape = textsecure.PreKeyWhisperMessage.$Properties;
    }

    /**
     * Properties of a KeyExchangeMessage.
     * @deprecated Use textsecure.KeyExchangeMessage.$Properties instead.
     */
    interface IKeyExchangeMessage extends textsecure.KeyExchangeMessage.$Properties {
    }

    /** Represents a KeyExchangeMessage. */
    class KeyExchangeMessage {

        /**
         * Constructs a new KeyExchangeMessage.
         * @param [properties] Properties to set
         */
        constructor(properties?: textsecure.KeyExchangeMessage.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** KeyExchangeMessage id. */
        id: number;

        /** KeyExchangeMessage baseKey. */
        baseKey: Uint8Array;

        /** KeyExchangeMessage ephemeralKey. */
        ephemeralKey: Uint8Array;

        /** KeyExchangeMessage identityKey. */
        identityKey: Uint8Array;

        /** KeyExchangeMessage baseKeySignature. */
        baseKeySignature: Uint8Array;

        /**
         * Creates a new KeyExchangeMessage instance using the specified properties.
         * @param [properties] Properties to set
         * @returns KeyExchangeMessage instance
         */
        static create(properties: textsecure.KeyExchangeMessage.$Shape): textsecure.KeyExchangeMessage & textsecure.KeyExchangeMessage.$Shape;
        static create(properties?: textsecure.KeyExchangeMessage.$Properties): textsecure.KeyExchangeMessage;

        /**
         * Encodes the specified KeyExchangeMessage message. Does not implicitly {@link textsecure.KeyExchangeMessage.verify|verify} messages.
         * @param message KeyExchangeMessage message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: textsecure.KeyExchangeMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a KeyExchangeMessage message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {textsecure.KeyExchangeMessage & textsecure.KeyExchangeMessage.$Shape} KeyExchangeMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): textsecure.KeyExchangeMessage & textsecure.KeyExchangeMessage.$Shape;

        /**
         * Gets the type url for KeyExchangeMessage
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace KeyExchangeMessage {

        /** Properties of a KeyExchangeMessage. */
        interface $Properties {

            /** KeyExchangeMessage id */
            id?: (number|null);

            /** KeyExchangeMessage baseKey */
            baseKey?: (Uint8Array|null);

            /** KeyExchangeMessage ephemeralKey */
            ephemeralKey?: (Uint8Array|null);

            /** KeyExchangeMessage identityKey */
            identityKey?: (Uint8Array|null);

            /** KeyExchangeMessage baseKeySignature */
            baseKeySignature?: (Uint8Array|null);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of a KeyExchangeMessage. */
        type $Shape = textsecure.KeyExchangeMessage.$Properties;
    }

    /**
     * Properties of an IncomingPushMessageSignal.
     * @deprecated Use textsecure.IncomingPushMessageSignal.$Properties instead.
     */
    interface IIncomingPushMessageSignal extends textsecure.IncomingPushMessageSignal.$Properties {
    }

    /** Represents an IncomingPushMessageSignal. */
    class IncomingPushMessageSignal {

        /**
         * Constructs a new IncomingPushMessageSignal.
         * @param [properties] Properties to set
         */
        constructor(properties?: textsecure.IncomingPushMessageSignal.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** IncomingPushMessageSignal type. */
        type: textsecure.IncomingPushMessageSignal.Type;

        /** IncomingPushMessageSignal source. */
        source: string;

        /** IncomingPushMessageSignal sourceDevice. */
        sourceDevice: number;

        /** IncomingPushMessageSignal relay. */
        relay: string;

        /** IncomingPushMessageSignal timestamp. */
        timestamp: number;

        /** IncomingPushMessageSignal message. */
        message: Uint8Array;

        /**
         * Creates a new IncomingPushMessageSignal instance using the specified properties.
         * @param [properties] Properties to set
         * @returns IncomingPushMessageSignal instance
         */
        static create(properties: textsecure.IncomingPushMessageSignal.$Shape): textsecure.IncomingPushMessageSignal & textsecure.IncomingPushMessageSignal.$Shape;
        static create(properties?: textsecure.IncomingPushMessageSignal.$Properties): textsecure.IncomingPushMessageSignal;

        /**
         * Encodes the specified IncomingPushMessageSignal message. Does not implicitly {@link textsecure.IncomingPushMessageSignal.verify|verify} messages.
         * @param message IncomingPushMessageSignal message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: textsecure.IncomingPushMessageSignal.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an IncomingPushMessageSignal message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {textsecure.IncomingPushMessageSignal & textsecure.IncomingPushMessageSignal.$Shape} IncomingPushMessageSignal
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): textsecure.IncomingPushMessageSignal & textsecure.IncomingPushMessageSignal.$Shape;

        /**
         * Gets the type url for IncomingPushMessageSignal
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace IncomingPushMessageSignal {

        /** Properties of an IncomingPushMessageSignal. */
        interface $Properties {

            /** IncomingPushMessageSignal type */
            type?: (textsecure.IncomingPushMessageSignal.Type|null);

            /** IncomingPushMessageSignal source */
            source?: (string|null);

            /** IncomingPushMessageSignal sourceDevice */
            sourceDevice?: (number|null);

            /** IncomingPushMessageSignal relay */
            relay?: (string|null);

            /** IncomingPushMessageSignal timestamp */
            timestamp?: (number|null);

            /** IncomingPushMessageSignal message */
            message?: (Uint8Array|null);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of an IncomingPushMessageSignal. */
        type $Shape = textsecure.IncomingPushMessageSignal.$Properties;

        /** Type enum. */
        enum Type {

            /** UNKNOWN value */
            UNKNOWN = 0,

            /** CIPHERTEXT value */
            CIPHERTEXT = 1,

            /** KEY_EXCHANGE value */
            KEY_EXCHANGE = 2,

            /** PREKEY_BUNDLE value */
            PREKEY_BUNDLE = 3,

            /** PLAINTEXT value */
            PLAINTEXT = 4,

            /** RECEIPT value */
            RECEIPT = 5,

            /** PREKEY_BUNDLE_DEVICE_CONTROL value */
            PREKEY_BUNDLE_DEVICE_CONTROL = 6,

            /** DEVICE_CONTROL value */
            DEVICE_CONTROL = 7
        }
    }

    /**
     * Properties of a PushMessageContent.
     * @deprecated Use textsecure.PushMessageContent.$Properties instead.
     */
    interface IPushMessageContent extends textsecure.PushMessageContent.$Properties {
    }

    /** Represents a PushMessageContent. */
    class PushMessageContent {

        /**
         * Constructs a new PushMessageContent.
         * @param [properties] Properties to set
         */
        constructor(properties?: textsecure.PushMessageContent.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** PushMessageContent body. */
        body: string;

        /** PushMessageContent attachments. */
        attachments: textsecure.PushMessageContent.AttachmentPointer.$Properties[];

        /** PushMessageContent group. */
        group?: (textsecure.PushMessageContent.GroupContext.$Properties|null);

        /** PushMessageContent flags. */
        flags: number;

        /**
         * Creates a new PushMessageContent instance using the specified properties.
         * @param [properties] Properties to set
         * @returns PushMessageContent instance
         */
        static create(properties: textsecure.PushMessageContent.$Shape): textsecure.PushMessageContent & textsecure.PushMessageContent.$Shape;
        static create(properties?: textsecure.PushMessageContent.$Properties): textsecure.PushMessageContent;

        /**
         * Encodes the specified PushMessageContent message. Does not implicitly {@link textsecure.PushMessageContent.verify|verify} messages.
         * @param message PushMessageContent message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: textsecure.PushMessageContent.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a PushMessageContent message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {textsecure.PushMessageContent & textsecure.PushMessageContent.$Shape} PushMessageContent
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): textsecure.PushMessageContent & textsecure.PushMessageContent.$Shape;

        /**
         * Gets the type url for PushMessageContent
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace PushMessageContent {

        /** Properties of a PushMessageContent. */
        interface $Properties {

            /** PushMessageContent body */
            body?: (string|null);

            /** PushMessageContent attachments */
            attachments?: (textsecure.PushMessageContent.AttachmentPointer.$Properties[]|null);

            /** PushMessageContent group */
            group?: (textsecure.PushMessageContent.GroupContext.$Properties|null);

            /** PushMessageContent flags */
            flags?: (number|null);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of a PushMessageContent. */
        type $Shape = textsecure.PushMessageContent.$Properties;

        /**
         * Properties of an AttachmentPointer.
         * @deprecated Use textsecure.PushMessageContent.AttachmentPointer.$Properties instead.
         */
        interface IAttachmentPointer extends textsecure.PushMessageContent.AttachmentPointer.$Properties {
        }

        /** Represents an AttachmentPointer. */
        class AttachmentPointer {

            /**
             * Constructs a new AttachmentPointer.
             * @param [properties] Properties to set
             */
            constructor(properties?: textsecure.PushMessageContent.AttachmentPointer.$Properties);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];

            /** AttachmentPointer id. */
            id: number;

            /** AttachmentPointer contentType. */
            contentType: string;

            /** AttachmentPointer key. */
            key: Uint8Array;

            /**
             * Creates a new AttachmentPointer instance using the specified properties.
             * @param [properties] Properties to set
             * @returns AttachmentPointer instance
             */
            static create(properties: textsecure.PushMessageContent.AttachmentPointer.$Shape): textsecure.PushMessageContent.AttachmentPointer & textsecure.PushMessageContent.AttachmentPointer.$Shape;
            static create(properties?: textsecure.PushMessageContent.AttachmentPointer.$Properties): textsecure.PushMessageContent.AttachmentPointer;

            /**
             * Encodes the specified AttachmentPointer message. Does not implicitly {@link textsecure.PushMessageContent.AttachmentPointer.verify|verify} messages.
             * @param message AttachmentPointer message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            static encode(message: textsecure.PushMessageContent.AttachmentPointer.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an AttachmentPointer message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns {textsecure.PushMessageContent.AttachmentPointer & textsecure.PushMessageContent.AttachmentPointer.$Shape} AttachmentPointer
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): textsecure.PushMessageContent.AttachmentPointer & textsecure.PushMessageContent.AttachmentPointer.$Shape;

            /**
             * Gets the type url for AttachmentPointer
             * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns The type url
             */
            static getTypeUrl(prefix?: string): string;
        }

        namespace AttachmentPointer {

            /** Properties of an AttachmentPointer. */
            interface $Properties {

                /** AttachmentPointer id */
                id?: (number|null);

                /** AttachmentPointer contentType */
                contentType?: (string|null);

                /** AttachmentPointer key */
                key?: (Uint8Array|null);

                /** Unknown fields preserved while decoding when enabled */
                $unknowns?: Uint8Array[];
            }

            /** Shape of an AttachmentPointer. */
            type $Shape = textsecure.PushMessageContent.AttachmentPointer.$Properties;
        }

        /**
         * Properties of a GroupContext.
         * @deprecated Use textsecure.PushMessageContent.GroupContext.$Properties instead.
         */
        interface IGroupContext extends textsecure.PushMessageContent.GroupContext.$Properties {
        }

        /** Represents a GroupContext. */
        class GroupContext {

            /**
             * Constructs a new GroupContext.
             * @param [properties] Properties to set
             */
            constructor(properties?: textsecure.PushMessageContent.GroupContext.$Properties);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];

            /** GroupContext id. */
            id: Uint8Array;

            /** GroupContext type. */
            type: textsecure.PushMessageContent.GroupContext.Type;

            /** GroupContext name. */
            name: string;

            /** GroupContext members. */
            members: string[];

            /** GroupContext avatar. */
            avatar?: (textsecure.PushMessageContent.AttachmentPointer.$Properties|null);

            /**
             * Creates a new GroupContext instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GroupContext instance
             */
            static create(properties: textsecure.PushMessageContent.GroupContext.$Shape): textsecure.PushMessageContent.GroupContext & textsecure.PushMessageContent.GroupContext.$Shape;
            static create(properties?: textsecure.PushMessageContent.GroupContext.$Properties): textsecure.PushMessageContent.GroupContext;

            /**
             * Encodes the specified GroupContext message. Does not implicitly {@link textsecure.PushMessageContent.GroupContext.verify|verify} messages.
             * @param message GroupContext message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            static encode(message: textsecure.PushMessageContent.GroupContext.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GroupContext message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns {textsecure.PushMessageContent.GroupContext & textsecure.PushMessageContent.GroupContext.$Shape} GroupContext
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): textsecure.PushMessageContent.GroupContext & textsecure.PushMessageContent.GroupContext.$Shape;

            /**
             * Gets the type url for GroupContext
             * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
             * @returns The type url
             */
            static getTypeUrl(prefix?: string): string;
        }

        namespace GroupContext {

            /** Properties of a GroupContext. */
            interface $Properties {

                /** GroupContext id */
                id?: (Uint8Array|null);

                /** GroupContext type */
                type?: (textsecure.PushMessageContent.GroupContext.Type|null);

                /** GroupContext name */
                name?: (string|null);

                /** GroupContext members */
                members?: (string[]|null);

                /** GroupContext avatar */
                avatar?: (textsecure.PushMessageContent.AttachmentPointer.$Properties|null);

                /** Unknown fields preserved while decoding when enabled */
                $unknowns?: Uint8Array[];
            }

            /** Shape of a GroupContext. */
            type $Shape = textsecure.PushMessageContent.GroupContext.$Properties;

            /** Type enum. */
            enum Type {

                /** UNKNOWN value */
                UNKNOWN = 0,

                /** UPDATE value */
                UPDATE = 1,

                /** DELIVER value */
                DELIVER = 2,

                /** QUIT value */
                QUIT = 3
            }
        }

        /** Flags enum. */
        enum Flags {

            /** END_SESSION value */
            END_SESSION = 1
        }
    }
}

/** Namespace omemo. */
export namespace omemo {

    /**
     * Properties of a OMEMOMessage.
     * @deprecated Use omemo.OMEMOMessage.$Properties instead.
     */
    interface IOMEMOMessage extends omemo.OMEMOMessage.$Properties {
    }

    /** Represents a OMEMOMessage. */
    class OMEMOMessage {

        /**
         * Constructs a new OMEMOMessage.
         * @param [properties] Properties to set
         */
        constructor(properties?: omemo.OMEMOMessage.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** OMEMOMessage n. */
        n: number;

        /** OMEMOMessage pn. */
        pn: number;

        /** OMEMOMessage dh_pub. */
        dh_pub: Uint8Array;

        /** OMEMOMessage ciphertext. */
        ciphertext: Uint8Array;

        /**
         * Creates a new OMEMOMessage instance using the specified properties.
         * @param [properties] Properties to set
         * @returns OMEMOMessage instance
         */
        static create(properties: omemo.OMEMOMessage.$Shape): omemo.OMEMOMessage & omemo.OMEMOMessage.$Shape;
        static create(properties?: omemo.OMEMOMessage.$Properties): omemo.OMEMOMessage;

        /**
         * Encodes the specified OMEMOMessage message. Does not implicitly {@link omemo.OMEMOMessage.verify|verify} messages.
         * @param message OMEMOMessage message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: omemo.OMEMOMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a OMEMOMessage message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {omemo.OMEMOMessage & omemo.OMEMOMessage.$Shape} OMEMOMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): omemo.OMEMOMessage & omemo.OMEMOMessage.$Shape;

        /**
         * Gets the type url for OMEMOMessage
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace OMEMOMessage {

        /** Properties of a OMEMOMessage. */
        interface $Properties {

            /** OMEMOMessage n */
            n: number;

            /** OMEMOMessage pn */
            pn: number;

            /** OMEMOMessage dh_pub */
            dh_pub: Uint8Array;

            /** OMEMOMessage ciphertext */
            ciphertext?: (Uint8Array|null);

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of a OMEMOMessage. */
        type $Shape = omemo.OMEMOMessage.$Properties;
    }

    /**
     * Properties of a OMEMOAuthenticatedMessage.
     * @deprecated Use omemo.OMEMOAuthenticatedMessage.$Properties instead.
     */
    interface IOMEMOAuthenticatedMessage extends omemo.OMEMOAuthenticatedMessage.$Properties {
    }

    /** Represents a OMEMOAuthenticatedMessage. */
    class OMEMOAuthenticatedMessage {

        /**
         * Constructs a new OMEMOAuthenticatedMessage.
         * @param [properties] Properties to set
         */
        constructor(properties?: omemo.OMEMOAuthenticatedMessage.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** OMEMOAuthenticatedMessage mac. */
        mac: Uint8Array;

        /** OMEMOAuthenticatedMessage message. */
        message: Uint8Array;

        /**
         * Creates a new OMEMOAuthenticatedMessage instance using the specified properties.
         * @param [properties] Properties to set
         * @returns OMEMOAuthenticatedMessage instance
         */
        static create(properties: omemo.OMEMOAuthenticatedMessage.$Shape): omemo.OMEMOAuthenticatedMessage & omemo.OMEMOAuthenticatedMessage.$Shape;
        static create(properties?: omemo.OMEMOAuthenticatedMessage.$Properties): omemo.OMEMOAuthenticatedMessage;

        /**
         * Encodes the specified OMEMOAuthenticatedMessage message. Does not implicitly {@link omemo.OMEMOAuthenticatedMessage.verify|verify} messages.
         * @param message OMEMOAuthenticatedMessage message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: omemo.OMEMOAuthenticatedMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a OMEMOAuthenticatedMessage message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {omemo.OMEMOAuthenticatedMessage & omemo.OMEMOAuthenticatedMessage.$Shape} OMEMOAuthenticatedMessage
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): omemo.OMEMOAuthenticatedMessage & omemo.OMEMOAuthenticatedMessage.$Shape;

        /**
         * Gets the type url for OMEMOAuthenticatedMessage
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace OMEMOAuthenticatedMessage {

        /** Properties of a OMEMOAuthenticatedMessage. */
        interface $Properties {

            /** OMEMOAuthenticatedMessage mac */
            mac: Uint8Array;

            /** OMEMOAuthenticatedMessage message */
            message: Uint8Array;

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of a OMEMOAuthenticatedMessage. */
        type $Shape = omemo.OMEMOAuthenticatedMessage.$Properties;
    }

    /**
     * Properties of a OMEMOKeyExchange.
     * @deprecated Use omemo.OMEMOKeyExchange.$Properties instead.
     */
    interface IOMEMOKeyExchange extends omemo.OMEMOKeyExchange.$Properties {
    }

    /** Represents a OMEMOKeyExchange. */
    class OMEMOKeyExchange {

        /**
         * Constructs a new OMEMOKeyExchange.
         * @param [properties] Properties to set
         */
        constructor(properties?: omemo.OMEMOKeyExchange.$Properties);

        /** Unknown fields preserved while decoding when enabled */
        $unknowns?: Uint8Array[];

        /** OMEMOKeyExchange pk_id. */
        pk_id: number;

        /** OMEMOKeyExchange spk_id. */
        spk_id: number;

        /** OMEMOKeyExchange ik. */
        ik: Uint8Array;

        /** OMEMOKeyExchange ek. */
        ek: Uint8Array;

        /** OMEMOKeyExchange message. */
        message: omemo.OMEMOAuthenticatedMessage.$Properties;

        /**
         * Creates a new OMEMOKeyExchange instance using the specified properties.
         * @param [properties] Properties to set
         * @returns OMEMOKeyExchange instance
         */
        static create(properties: omemo.OMEMOKeyExchange.$Shape): omemo.OMEMOKeyExchange & omemo.OMEMOKeyExchange.$Shape;
        static create(properties?: omemo.OMEMOKeyExchange.$Properties): omemo.OMEMOKeyExchange;

        /**
         * Encodes the specified OMEMOKeyExchange message. Does not implicitly {@link omemo.OMEMOKeyExchange.verify|verify} messages.
         * @param message OMEMOKeyExchange message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        static encode(message: omemo.OMEMOKeyExchange.$Properties, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a OMEMOKeyExchange message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns {omemo.OMEMOKeyExchange & omemo.OMEMOKeyExchange.$Shape} OMEMOKeyExchange
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): omemo.OMEMOKeyExchange & omemo.OMEMOKeyExchange.$Shape;

        /**
         * Gets the type url for OMEMOKeyExchange
         * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
         * @returns The type url
         */
        static getTypeUrl(prefix?: string): string;
    }

    namespace OMEMOKeyExchange {

        /** Properties of a OMEMOKeyExchange. */
        interface $Properties {

            /** OMEMOKeyExchange pk_id */
            pk_id: number;

            /** OMEMOKeyExchange spk_id */
            spk_id: number;

            /** OMEMOKeyExchange ik */
            ik: Uint8Array;

            /** OMEMOKeyExchange ek */
            ek: Uint8Array;

            /** OMEMOKeyExchange message */
            message: omemo.OMEMOAuthenticatedMessage.$Properties;

            /** Unknown fields preserved while decoding when enabled */
            $unknowns?: Uint8Array[];
        }

        /** Shape of a OMEMOKeyExchange. */
        type $Shape = omemo.OMEMOKeyExchange.$Properties;
    }
}

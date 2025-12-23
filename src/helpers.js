/*
 * vim: ts=4:sw=4
 */

const util = (libsignal.util = (function () {
    "use strict";

    return {
        toString: function (thing) {
            if (typeof thing == "string") {
                return thing;
            }
            return new dcodeIO.ByteBuffer.wrap(thing).toString("binary");
        },

        toArrayBuffer: function (thing) {
            if (thing === undefined) {
                return undefined;
            }
            if (thing instanceof ArrayBuffer) {
                return thing;
            }
            if (thing instanceof Uint8Array) {
                return thing.buffer;
            }
            if (typeof thing !== "string") {
                throw new Error(
                    "Tried to convert a non-string of type " + typeof thing + " to an array buffer"
                );
            }
            return new dcodeIO.ByteBuffer.wrap(thing, "binary").toArrayBuffer();
        },

        isEqual: function (a, b) {
            // TODO: Special-case arraybuffers, etc
            if (a === undefined || b === undefined) {
                return false;
            }
            a = util.toString(a);
            b = util.toString(b);
            const maxLength = Math.max(a.length, b.length);
            if (maxLength < 5) {
                throw new Error("a/b compare too short");
            }
            return (
                a.substring(0, Math.min(maxLength, a.length)) ==
                b.substring(0, Math.min(maxLength, b.length))
            );
        },
    };
})());

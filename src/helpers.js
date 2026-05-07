/*
 * vim: ts=4:sw=4
 */

const util = (libomemo.util = (function () {
    "use strict";

    return {
        toString: function (thing) {
            if (typeof thing == "string") {
                return thing;
            }
            const bytes = new Uint8Array(thing);
            let str = "";
            for (let i = 0; i < bytes.length; i++) {
                str += String.fromCharCode(bytes[i]);
            }
            return str;
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
            const len = thing.length;
            const buf = new ArrayBuffer(len);
            const view = new Uint8Array(buf);
            for (let i = 0; i < len; i++) {
                view[i] = thing.charCodeAt(i) & 0xff;
            }
            return buf;
        },

        normalizeBuffer: function (input, encoding) {
            if (input instanceof ArrayBuffer) {
                return new Uint8Array(input);
            }
            if (input instanceof Uint8Array) {
                return input;
            }
            if (typeof input !== "string") {
                throw new Error("Expected string or buffer");
            }
            switch (encoding) {
                case "binary": {
                    const buf = new Uint8Array(input.length);
                    for (let i = 0; i < input.length; i++) {
                        buf[i] = input.charCodeAt(i);
                    }
                    return buf;
                }
                case "base64": {
                    const raw = atob(input);
                    const buf = new Uint8Array(raw.length);
                    for (let i = 0; i < raw.length; i++) {
                        buf[i] = raw.charCodeAt(i);
                    }
                    return buf;
                }
                case "hex": {
                    const len = input.length / 2;
                    const buf = new Uint8Array(len);
                    for (let i = 0; i < len; i++) {
                        buf[i] = parseInt(input.substr(i * 2, 2), 16);
                    }
                    return buf;
                }
                case "utf8":
                case "utf-8":
                    return new TextEncoder().encode(input);
                default:
                    throw new Error("Unsupported encoding: " + encoding);
            }
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

import { JSONValue } from "./session/types";

type BinaryData = string | ArrayBuffer | Uint8Array;

export function isNonNegativeInteger(n: unknown): n is number {
    return typeof n === "number" && n % 1 === 0 && n >= 0;
}

function toString(thing: BinaryData): string {
    if (typeof thing === "string") {
        return thing;
    }
    const bytes = new Uint8Array(thing);
    let str = "";
    for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

function ensureStringed(thing: unknown): JSONValue {
    if (typeof thing === "string" || typeof thing === "number" || typeof thing === "boolean") {
        return thing;
    } else if (thing instanceof ArrayBuffer || thing instanceof Uint8Array) {
        return util.toString(thing);
    } else if (Array.isArray(thing)) {
        return thing.map(ensureStringed);
    } else if (thing === Object(thing)) {
        const obj: { [key: string]: JSONValue } = {};
        for (const key in thing as object) {
            if (!Object.prototype.hasOwnProperty.call(thing, key)) {
                continue;
            }
            const val = (thing as Record<string, unknown>)[key];
            if (val === undefined) {
                continue;
            }
            try {
                obj[key] = ensureStringed(val);
            } catch (ex) {
                console.log("Error serializing key", key);
                throw ex;
            }
        }
        return obj;
    } else if (thing === null) {
        return null;
    } else {
        throw new Error(`unsure of how to jsonify object of type ${typeof thing}`);
    }
}

export function jsonThing(thing: unknown): string {
    return JSON.stringify(ensureStringed(thing));
}

export function strToBytes(s: string): ArrayBuffer {
    const buf = new ArrayBuffer(s.length);
    const view = new Uint8Array(buf);
    for (let i = 0; i < s.length; i++) {
        view[i] = s.charCodeAt(i) & 0xff;
    }
    return buf;
}

function toArrayBuffer(thing: BinaryData | undefined): ArrayBuffer | undefined {
    if (thing === undefined) {
        return undefined;
    }
    if (thing instanceof ArrayBuffer) {
        return thing;
    }
    if (thing instanceof Uint8Array) {
        return thing.buffer as ArrayBuffer;
    }
    if (typeof thing !== "string") {
        throw new Error(`Tried to convert a non-string of type ${typeof thing} to an array buffer`);
    }

    return strToBytes(thing);
}

function normalizeBuffer(input: BinaryData, encoding: string): Uint8Array {
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
                buf[i] = parseInt(input.substring(i * 2, i * 2 + 2), 16);
            }
            return buf;
        }
        case "utf8":
        case "utf-8":
            return new TextEncoder().encode(input);
        default:
            throw new Error(`Unsupported encoding: ${encoding}`);
    }
}

function isEqual(a: BinaryData, b: BinaryData): boolean {
    if (a === undefined || b === undefined) {
        return false;
    }
    const aStr = toString(a);
    const bStr = toString(b);
    const maxLength = Math.max(aStr.length, bStr.length);
    if (maxLength < 5) {
        throw new Error("a/b compare too short");
    }
    return (
        aStr.substring(0, Math.min(maxLength, aStr.length)) ===
        bStr.substring(0, Math.min(maxLength, bStr.length))
    );
}

export const util = { toString, toArrayBuffer, normalizeBuffer, isEqual };

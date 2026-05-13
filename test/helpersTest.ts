import { assert } from "chai";
import { util } from "../src/index.js";

describe("util", function () {
    describe("isEqual", function () {
        it("returns false when either a or b is undefined", function () {
            assert.isFalse(util.isEqual("defined value", undefined as unknown as string));
            assert.isFalse(util.isEqual(undefined as unknown as string, "defined value"));
        });
        it("returns true when a and b are equal", function () {
            const a = "same value";
            const b = "same value";
            assert.isTrue(util.isEqual(a, b));
        });
        it("returns false when a and b are not equal", function () {
            const a = "same value";
            const b = "diferent value";
            assert.isFalse(util.isEqual(a, b));
        });
        it("throws an error when a/b compare is too short", function () {
            const a = "1234";
            const b = "1234";
            assert.throw(() => util.isEqual(a, b), Error, /a\/b compare too short/);
        });
    });

    describe("toString", function () {
        it("returns the same string unchanged", function () {
            assert.strictEqual(util.toString("hello"), "hello");
        });

        it("converts an ArrayBuffer of all-zero bytes to a binary string", function () {
            const buf = new ArrayBuffer(3);
            const result = util.toString(buf);
            assert.strictEqual(result.length, 3);
            assert.strictEqual(result, "\x00\x00\x00");
        });

        it("converts an ArrayBuffer with 0xFF bytes to a binary string", function () {
            const buf = new ArrayBuffer(2);
            const view = new Uint8Array(buf);
            view[0] = 0xff;
            view[1] = 0xff;
            const result = util.toString(buf);
            assert.strictEqual(result.length, 2);
            assert.strictEqual(result.charCodeAt(0), 0xff);
            assert.strictEqual(result.charCodeAt(1), 0xff);
        });

        it("converts a Uint8Array to a binary string", function () {
            const arr = new Uint8Array([65, 66, 67]); // "ABC"
            const result = util.toString(arr);
            assert.strictEqual(result, "ABC");
        });

        it("handles byte values 0 through 255 correctly", function () {
            const buf = new ArrayBuffer(256);
            const view = new Uint8Array(buf);
            for (let i = 0; i < 256; i++) {
                view[i] = i;
            }
            const result = util.toString(buf);
            assert.strictEqual(result.length, 256);
            for (let i = 0; i < 256; i++) {
                assert.strictEqual(result.charCodeAt(i), i);
            }
        });

        it("handles empty ArrayBuffer", function () {
            const buf = new ArrayBuffer(0);
            const result = util.toString(buf);
            assert.strictEqual(result, "");
        });
    });

    describe("toArrayBuffer", function () {
        it("returns undefined when passed undefined", function () {
            assert.isUndefined(util.toArrayBuffer(undefined));
        });

        it("returns the same ArrayBuffer unchanged", function () {
            const buf = new ArrayBuffer(4);
            assert.strictEqual(util.toArrayBuffer(buf), buf);
        });

        it("returns .buffer from a Uint8Array", function () {
            const buf = new ArrayBuffer(4);
            const arr = new Uint8Array(buf);
            assert.strictEqual(util.toArrayBuffer(arr), buf);
        });

        it("converts a binary string to an ArrayBuffer", function () {
            const str = "ABC";
            const result = util.toArrayBuffer(str);
            assert.instanceOf(result, ArrayBuffer);
            assert.strictEqual(result.byteLength, 3);
            const view = new Uint8Array(result);
            assert.strictEqual(view[0], 65);
            assert.strictEqual(view[1], 66);
            assert.strictEqual(view[2], 67);
        });

        it("roundtrips binary string through toArrayBuffer and toString", function () {
            const str = "\x00\xFF\x80\x7F\x01";
            const buf = util.toArrayBuffer(str)!;
            const back = util.toString(buf);
            assert.strictEqual(back, str);
        });

        it("roundtrips ArrayBuffer through toString and toArrayBuffer", function () {
            const buf = new ArrayBuffer(5);
            const view = new Uint8Array(buf);
            view.set([0, 127, 128, 255, 42]);
            const str = util.toString(buf);
            const back = util.toArrayBuffer(str)!;
            const backView = new Uint8Array(back);
            for (let i = 0; i < 5; i++) {
                assert.strictEqual(backView[i], view[i]);
            }
        });

        it("throws for non-string, non-buffer types", function () {
            assert.throw(
                function () {
                    util.toArrayBuffer(42 as unknown as string);
                },
                Error,
                /non-string/
            );
            assert.throw(
                function () {
                    util.toArrayBuffer({} as unknown as string);
                },
                Error,
                /non-string/
            );
        });

        it("handles empty binary string", function () {
            const result = util.toArrayBuffer("");
            assert.instanceOf(result, ArrayBuffer);
            assert.strictEqual(result.byteLength, 0);
        });
    });
});

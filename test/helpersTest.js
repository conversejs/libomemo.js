/* vim: ts=4:sw=4 */
/* global assert */

'use strict';
describe('util', function() {
    describe("isEqual", function(){
        it('returns false when a or b is undefined', function(){
            assert.isFalse(util.isEqual("defined value", undefined));
            assert.isFalse(util.isEqual(undefined, "defined value"));
        });
        it('returns true when a and b are equal', function(){
            const a = "same value";
            const b = "same value";
            assert.isTrue(util.isEqual(a, b));
        });
        it('returns false when a and b are not equal', function(){
            const a = "same value";
            const b = "diferent value";
            assert.isFalse(util.isEqual(a, b));
        });
        it('throws an error when a/b compare is too short', function(){
            const a = "1234";
            const b = "1234";
            assert.throw(function() { util.isEqual(a, b) },
                        Error, /a\/b compare too short/);
        });
    });
});

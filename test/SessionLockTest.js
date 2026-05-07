"use strict";
window.assert = chai.assert;

describe("SessionLock", function () {
    const { assert } = chai;

    describe("queueJobForNumber", function () {
        it("executes a job and returns its result", async function () {
            const result = await Internal.SessionLock.queueJobForNumber("test1", () =>
                Promise.resolve(42)
            );
            assert.strictEqual(result, 42);
        });

        it("serializes jobs for the same number", async function () {
            const order = [];
            const number = "serialize_test";

            await Internal.SessionLock.queueJobForNumber(number, () => {
                order.push("start1");
                return new Promise((resolve) => {
                    setTimeout(() => {
                        order.push("end1");
                        resolve();
                    }, 20);
                });
            });

            await Internal.SessionLock.queueJobForNumber(number, () => {
                order.push("start2");
                return new Promise((resolve) => {
                    order.push("end2");
                    resolve();
                });
            });

            assert.deepEqual(order, ["start1", "end1", "start2", "end2"]);
        });

        it("allows concurrent execution for different numbers", function () {
            const order = [];
            const job1 = Internal.SessionLock.queueJobForNumber("num1", function () {
                order.push("start1");
                return new Promise(function (resolve) {
                    setTimeout(function () {
                        order.push("end1");
                        resolve();
                    }, 20);
                });
            });

            const job2 = Internal.SessionLock.queueJobForNumber("num2", function () {
                order.push("start2");
                return new Promise(function (resolve) {
                    order.push("end2");
                    resolve();
                });
            });

            return Promise.all([job1, job2]).then(function () {
                assert.strictEqual(order[0], "start1");
                assert.strictEqual(order[1], "start2");
                assert.strictEqual(order[2], "end2");
                assert.strictEqual(order[3], "end1");
            });
        });

        it("propagates errors from the job", function () {
            return Internal.SessionLock.queueJobForNumber("error_test", function () {
                return Promise.reject(new Error("test failure"));
            }).then(
                function () {
                    assert.fail("Expected rejection");
                },
                function (err) {
                    assert.strictEqual(err.message, "test failure");
                }
            );
        });

        it("continues running subsequent jobs after a job fails", function () {
            const number = "continue_after_error";
            const results = [];

            return Internal.SessionLock.queueJobForNumber(number, function () {
                return Promise.reject(new Error("fail"));
            })
                .then(
                    function () {
                        results.push("should not reach");
                    },
                    function () {
                        results.push("error");
                    }
                )
                .then(function () {
                    return Internal.SessionLock.queueJobForNumber(number, function () {
                        results.push("second");
                        return Promise.resolve("ok");
                    });
                })
                .then(function (result) {
                    assert.strictEqual(result, "ok");
                    assert.deepEqual(results, ["error", "second"]);
                });
        });
    });
});

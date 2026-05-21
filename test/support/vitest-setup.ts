import { beforeAll, afterAll, beforeEach, afterEach, describe, it, test, expect, vi } from "vitest";

// Vitest 4 does not inject globals automatically with `globals: true`.
// We need to manually attach them to globalThis for Mocha-compatible test files.
Object.assign(globalThis, {
    describe,
    it,
    test,
    expect,
    before: beforeAll,
    after: afterAll,
    beforeAll,
    afterAll,
    beforeEach,
    afterEach,
    vi,
});

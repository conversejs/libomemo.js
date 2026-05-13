import { assert } from "chai";
import { SessionRecord } from "../src/session/record.js";

describe("SessionRecord", function () {
    describe("constructor", function () {
        it("creates a record with empty sessions and v1 version", function () {
            const record = new SessionRecord();
            assert.deepEqual(record.sessions, {});
            assert.strictEqual(record.version, "v1");
        });
    });

    describe("serialize", function () {
        it("serializes an empty record", function () {
            const record = new SessionRecord();
            const json = record.serialize();
            assert.isString(json);
            const data = JSON.parse(json);
            assert.deepEqual(data.sessions, {});
            assert.strictEqual(data.version, "v1");
        });

        it("serializes a record with a session", function () {
            const record = new SessionRecord();
            record.sessions["mykey"] = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "mykey", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            const json = record.serialize();
            const data = JSON.parse(json);
            assert.strictEqual(data.sessions["mykey"].registrationId, 42);
            assert.strictEqual(data.sessions["mykey"].indexInfo.closed, -1);
            assert.strictEqual(data.version, "v1");
        });
    });

    describe("deserialize", function () {
        it("roundtrips an empty record", function () {
            const original = new SessionRecord();
            const restored = SessionRecord.deserialize(original.serialize());
            assert.deepEqual(restored.sessions, {});
            assert.strictEqual(restored.version, "v1");
        });

        it("roundtrips a record with sessions", function () {
            const original = new SessionRecord();
            original.sessions["key1"] = {
                registrationId: 1,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: 1234, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            original.sessions["key2"] = {
                registrationId: 2,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key2", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            const restored = SessionRecord.deserialize(original.serialize());
            assert.strictEqual(Object.keys(restored.sessions).length, 2);
            assert.strictEqual(restored.sessions["key1"].registrationId, 1);
            assert.strictEqual(restored.sessions["key2"].registrationId, 2);
            assert.strictEqual(restored.sessions["key1"].indexInfo.closed, 1234);
            assert.strictEqual(restored.sessions["key2"].indexInfo.closed, -1);
        });

        it("throws for sessions that is null", function () {
            const json = JSON.stringify({ version: "v1", sessions: null });
            assert.throw(
                function () {
                    SessionRecord.deserialize(json);
                },
                Error,
                /deserializing/
            );
        });

        it("throws for sessions that is an array", function () {
            const json = JSON.stringify({ version: "v1", sessions: [] });
            assert.throw(
                function () {
                    SessionRecord.deserialize(json);
                },
                Error,
                /deserializing/
            );
        });

        it("throws for sessions that is a string", function () {
            const json = JSON.stringify({ version: "v1", sessions: "notanobject" });
            assert.throw(
                function () {
                    SessionRecord.deserialize(json);
                },
                Error,
                /deserializing/
            );
        });
    });

    describe("hasOpenSession", function () {
        it("returns true when an open session has a registrationId", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            assert.isTrue(record.hasOpenSession());
        });

        it("returns false when no session is open", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: Date.now(), baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            assert.isFalse(record.hasOpenSession());
        });

        it("returns false when sessions is empty", function () {
            const record = new SessionRecord();
            assert.isFalse(record.hasOpenSession());
        });
    });

    describe("getOpenSession", function () {
        it("returns the open session", function () {
            const record = new SessionRecord();
            const session: any = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "open", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["open"] = session;
            assert.strictEqual(record.getOpenSession(), session);
        });

        it("returns undefined when no sessions are open", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: Date.now(), baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            assert.isUndefined(record.getOpenSession());
        });

        it("returns undefined when sessions is empty", function () {
            const record = new SessionRecord();
            assert.isUndefined(record.getOpenSession());
        });

        it("throws when there are multiple open sessions", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 1,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key2"] = {
                registrationId: 2,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key2", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            assert.throw(
                function () {
                    record.getOpenSession();
                },
                Error,
                /multiple open sessions/
            );
        });
    });

    describe("archiveCurrentState", function () {
        it("sets the closed timestamp on the open session", function () {
            const record = new SessionRecord();
            const session: any = {
                registrationId: 42,
                oldRatchetList: [],
                currentRatchet: {} as any,
                indexInfo: { closed: -1, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key1"] = session;
            const before = Date.now();
            record.archiveCurrentState();
            const after = Date.now();
            assert.isAtLeast(session.indexInfo.closed, before);
            assert.isAtMost(session.indexInfo.closed, after);
            assert.notStrictEqual(session.indexInfo.closed, -1);
        });

        it("does nothing when no session is open", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 42,
                oldRatchetList: [],
                currentRatchet: {} as any,
                indexInfo: { closed: 1000, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.archiveCurrentState();
            assert.strictEqual(record.sessions["key1"].indexInfo.closed, 1000);
        });
    });

    describe("promoteState", function () {
        it("sets closed to -1 on a closed session", function () {
            const record = new SessionRecord();
            const session: any = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: Date.now(), baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.promoteState(session);
            assert.strictEqual(session.indexInfo.closed, -1);
        });
    });

    describe("deleteAllSessions", function () {
        it("removes all sessions", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 1,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key2"] = {
                registrationId: 2,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: Date.now(), baseKey: "key2", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.deleteAllSessions();
            assert.deepEqual(record.sessions, {});
        });
    });

    describe("detectDuplicateOpenSessions", function () {
        it("does not throw when at most one session is open", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 1,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key2"] = {
                registrationId: 2,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: Date.now(), baseKey: "key2", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            assert.doesNotThrow(function () {
                record.detectDuplicateOpenSessions();
            });
        });

        it("throws when multiple sessions are open", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 1,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key2"] = {
                registrationId: 2,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key2", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            assert.throw(
                function () {
                    record.detectDuplicateOpenSessions();
                },
                Error,
                /multiple open sessions/
            );
        });
    });

    describe("getSessions", function () {
        it("returns sessions sorted by close time, with open session last", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 1,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: 3000, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key2"] = {
                registrationId: 2,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: -1, baseKey: "key2", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key3"] = {
                registrationId: 3,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: 1000, baseKey: "key3", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.sessions["key4"] = {
                registrationId: 4,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { closed: 2000, baseKey: "key4", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            const sessions = record.getSessions();
            assert.strictEqual(sessions.length, 4);
            assert.strictEqual(sessions[0].registrationId, 3);
            assert.strictEqual(sessions[1].registrationId, 4);
            assert.strictEqual(sessions[2].registrationId, 1);
            assert.strictEqual(sessions[3].registrationId, 2);
            assert.strictEqual(sessions[3].indexInfo.closed, -1);
        });

        it("returns empty array when no sessions exist", function () {
            const record = new SessionRecord();
            assert.deepEqual(record.getSessions(), []);
        });
    });

    describe("getSessionByBaseKey", function () {
        it("returns the session for the given baseKey", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { baseKey: "key1", baseKeyType: 2, closed: -1, remoteIdentityKey: "x" as any },
            };
            assert.isObject(record.getSessionByBaseKey("key1" as any));
        });

        it("returns undefined when baseKeyType is OURS", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 42,
                currentRatchet: {} as any,
                oldRatchetList: [],
                indexInfo: { baseKey: "key1", baseKeyType: 1, closed: -1, remoteIdentityKey: "x" as any },
            };
            assert.isUndefined(record.getSessionByBaseKey("key1" as any));
        });
    });

    describe("serialize/deserialize preserves internal state", function () {
        it("archiveCurrentState survives serialize/deserialize", function () {
            const record = new SessionRecord();
            record.sessions["key1"] = {
                registrationId: 42,
                oldRatchetList: [],
                currentRatchet: {} as any,
                indexInfo: { closed: -1, baseKey: "key1", baseKeyType: 2, remoteIdentityKey: "x" as any },
            };
            record.archiveCurrentState();
            const closed = record.sessions["key1"].indexInfo.closed;

            const restored = SessionRecord.deserialize(record.serialize());
            assert.strictEqual(restored.sessions["key1"].indexInfo.closed, closed);
        });
    });
});

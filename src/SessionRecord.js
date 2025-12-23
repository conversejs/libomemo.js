/*
 * vim: ts=4:sw=4
 */

// eslint-disable-next-line no-redeclare
var Internal = Internal || {};

Internal.BaseKeyType = {
    OURS: 1,
    THEIRS: 2,
};
Internal.ChainType = {
    SENDING: 1,
    RECEIVING: 2,
};

Internal.SessionRecord = (function () {
    "use strict";
    const ARCHIVED_STATES_MAX_LENGTH = 40;
    const OLD_RATCHETS_MAX_LENGTH = 10;
    const SESSION_RECORD_VERSION = "v1";

    function ensureStringed(thing) {
        if (typeof thing == "string" || typeof thing == "number" || typeof thing == "boolean") {
            return thing;
        } else if (thing instanceof ArrayBuffer || thing instanceof Uint8Array) {
            return util.toString(thing);
        } else if (Array.isArray(thing)) {
            return thing.map(ensureStringed);
        } else if (thing === Object(thing)) {
            const obj = {};
            for (let key in thing) {
                if (!Object.prototype.hasOwnProperty.call(thing, key)) {
                    continue;
                }
                try {
                    obj[key] = ensureStringed(thing[key]);
                } catch (ex) {
                    console.log("Error serializing key", key);
                    throw ex;
                }
            }
            return obj;
        } else if (thing === null) {
            return null;
        } else {
            throw new Error("unsure of how to jsonify object of type " + typeof thing);
        }
    }

    function jsonThing(thing) {
        return JSON.stringify(ensureStringed(thing)); //TODO: jquery???
    }

    const migrations = [
        {
            version: "v1",
            // eslint-disable-next-line func-name-matching
            migrate: function migrateV1(data) {
                const sessions = data.sessions;
                let key;
                if (data.registrationId) {
                    for (key in sessions) {
                        if (!sessions[key].registrationId) {
                            sessions[key].registrationId = data.registrationId;
                        }
                    }
                } else {
                    for (key in sessions) {
                        if (sessions[key].indexInfo.closed === -1) {
                            console.log(
                                "V1 session storage migration error: registrationId",
                                data.registrationId,
                                "for open session version",
                                data.version
                            );
                        }
                    }
                }
            },
        },
    ];

    function migrate(data) {
        let run = data.version === undefined;
        for (let i = 0; i < migrations.length; ++i) {
            if (run) {
                migrations[i].migrate(data);
            } else if (migrations[i].version === data.version) {
                run = true;
            }
        }
        if (!run) {
            throw new Error("Error migrating SessionRecord");
        }
    }

    const SessionRecord = function () {
        this.sessions = {};
        this.version = SESSION_RECORD_VERSION;
    };

    SessionRecord.deserialize = function (serialized) {
        const data = JSON.parse(serialized);
        if (data.version !== SESSION_RECORD_VERSION) {
            migrate(data);
        }

        const record = new SessionRecord();
        record.sessions = data.sessions;
        if (
            record.sessions === undefined ||
            record.sessions === null ||
            typeof record.sessions !== "object" ||
            Array.isArray(record.sessions)
        ) {
            throw new Error("Error deserializing SessionRecord");
        }
        return record;
    };

    SessionRecord.prototype = {
        serialize: function () {
            return jsonThing({
                sessions: this.sessions,
                version: this.version,
            });
        },
        haveOpenSession: function () {
            const openSession = this.getOpenSession();
            return !!openSession && typeof openSession.registrationId === "number";
        },

        getSessionByBaseKey: function (baseKey) {
            const session = this.sessions[util.toString(baseKey)];
            if (session && session.indexInfo.baseKeyType === Internal.BaseKeyType.OURS) {
                console.log("Tried to lookup a session using our basekey");
                return undefined;
            }
            return session;
        },
        getSessionByRemoteEphemeralKey: function (remoteEphemeralKey) {
            this.detectDuplicateOpenSessions();
            const sessions = this.sessions;

            const searchKey = util.toString(remoteEphemeralKey);

            let openSession;
            for (let key in sessions) {
                if (!Object.prototype.hasOwnProperty.call(sessions, key)) {
                    continue;
                }
                if (sessions[key].indexInfo.closed == -1) {
                    openSession = sessions[key];
                }
                if (sessions[key][searchKey] !== undefined) {
                    return sessions[key];
                }
            }
            if (openSession !== undefined) {
                return openSession;
            }

            return undefined;
        },
        getOpenSession: function () {
            const sessions = this.sessions;
            if (sessions === undefined) {
                return undefined;
            }

            this.detectDuplicateOpenSessions();

            for (let key in sessions) {
                if (sessions[key].indexInfo.closed == -1) {
                    return sessions[key];
                }
            }
            return undefined;
        },
        detectDuplicateOpenSessions: function () {
            let openSession;
            const sessions = this.sessions;
            for (let key in sessions) {
                if (sessions[key].indexInfo.closed == -1) {
                    if (openSession !== undefined) {
                        throw new Error("Datastore inconsistensy: multiple open sessions");
                    }
                    openSession = sessions[key];
                }
            }
        },
        updateSessionState: function (session) {
            const sessions = this.sessions;

            this.removeOldChains(session);

            sessions[util.toString(session.indexInfo.baseKey)] = session;

            this.removeOldSessions();
        },
        getSessions: function () {
            // return an array of sessions ordered by time closed,
            // followed by the open session
            let list = [];
            let openSession;
            for (let k in this.sessions) {
                if (this.sessions[k].indexInfo.closed === -1) {
                    openSession = this.sessions[k];
                } else {
                    list.push(this.sessions[k]);
                }
            }
            list = list.sort(function (s1, s2) {
                return s1.indexInfo.closed - s2.indexInfo.closed;
            });
            if (openSession) {
                list.push(openSession);
            }
            return list;
        },
        archiveCurrentState: function () {
            const open_session = this.getOpenSession();
            if (open_session !== undefined) {
                console.log("closing session");
                open_session.indexInfo.closed = Date.now();
                this.updateSessionState(open_session);
            }
        },
        promoteState: function (session) {
            console.log("promoting session");
            session.indexInfo.closed = -1;
        },
        removeOldChains: function (session) {
            // Sending ratchets are always removed when we step because we never need them again
            // Receiving ratchets are added to the oldRatchetList, which we parse
            // here and remove all but the last ten.
            while (session.oldRatchetList.length > OLD_RATCHETS_MAX_LENGTH) {
                let index = 0;
                let oldest = session.oldRatchetList[0];
                for (let i = 0; i < session.oldRatchetList.length; i++) {
                    if (session.oldRatchetList[i].added < oldest.added) {
                        oldest = session.oldRatchetList[i];
                        index = i;
                    }
                }
                console.log("Deleting chain closed at", oldest.added);
                delete session[util.toString(oldest.ephemeralKey)];
                session.oldRatchetList.splice(index, 1);
            }
        },
        removeOldSessions: function () {
            // Retain only the last 20 sessions
            const sessions = this.sessions;
            let oldestBaseKey, oldestSession;
            while (Object.keys(sessions).length > ARCHIVED_STATES_MAX_LENGTH) {
                for (let key in sessions) {
                    if (!Object.prototype.hasOwnProperty.call(sessions, key)) {
                        continue;
                    }
                    const session = sessions[key];
                    if (
                        session.indexInfo.closed > -1 && // session is closed
                        (!oldestSession ||
                            session.indexInfo.closed < oldestSession.indexInfo.closed)
                    ) {
                        oldestBaseKey = key;
                        oldestSession = session;
                    }
                }
                console.log("Deleting session closed at", oldestSession.indexInfo.closed);
                delete sessions[util.toString(oldestBaseKey)];
            }
        },
        deleteAllSessions: function () {
            // Used primarily in session reset scenarios, where we really delete sessions
            this.sessions = {};
        },
    };

    return SessionRecord;
})();

import { util } from "./helpers.js";

export const BaseKeyType = {
    OURS: 1,
    THEIRS: 2,
};

export const ChainType = {
    SENDING: 1,
    RECEIVING: 2,
};

const ARCHIVED_STATES_MAX_LENGTH = 40;
const OLD_RATCHETS_MAX_LENGTH = 10;
const SESSION_RECORD_VERSION = "v1";

function ensureStringed(thing) {
    if (typeof thing === "string" || typeof thing === "number" || typeof thing === "boolean") {
        return thing;
    } else if (thing instanceof ArrayBuffer || thing instanceof Uint8Array) {
        return util.toString(thing);
    } else if (Array.isArray(thing)) {
        return thing.map(ensureStringed);
    } else if (thing === Object(thing)) {
        const obj = {};
        for (const key in thing) {
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
        throw new Error(`unsure of how to jsonify object of type ${typeof thing}`);
    }
}

function jsonThing(thing) {
    return JSON.stringify(ensureStringed(thing));
}

const migrations = [
    {
        version: "v1",
        migrate(data) {
            const sessions = data.sessions;
            if (data.registrationId) {
                for (const key in sessions) {
                    if (!sessions[key].registrationId) {
                        sessions[key].registrationId = data.registrationId;
                    }
                }
            } else {
                for (const key in sessions) {
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

export class SessionRecord {
    sessions = {};
    version = SESSION_RECORD_VERSION;

    static deserialize(serialized) {
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
    }

    serialize() {
        return jsonThing({
            sessions: this.sessions,
            version: this.version,
        });
    }

    haveOpenSession() {
        const openSession = this.getOpenSession();
        return !!openSession && typeof openSession.registrationId === "number";
    }

    getSessionByBaseKey(baseKey) {
        const session = this.sessions[util.toString(baseKey)];
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            console.log("Tried to lookup a session using our basekey");
            return undefined;
        }
        return session;
    }

    getSessionByRemoteEphemeralKey(remoteEphemeralKey) {
        this.detectDuplicateOpenSessions();
        const sessions = this.sessions;
        const searchKey = util.toString(remoteEphemeralKey);

        let openSession;
        for (const key in sessions) {
            if (!Object.prototype.hasOwnProperty.call(sessions, key)) {
                continue;
            }
            if (sessions[key].indexInfo.closed === -1) {
                openSession = sessions[key];
            }
            if (sessions[key][searchKey] !== undefined) {
                return sessions[key];
            }
        }
        return openSession;
    }

    getOpenSession() {
        const sessions = this.sessions;
        if (sessions === undefined) {
            return undefined;
        }

        this.detectDuplicateOpenSessions();

        for (const key in sessions) {
            if (sessions[key].indexInfo.closed === -1) {
                return sessions[key];
            }
        }
        return undefined;
    }

    detectDuplicateOpenSessions() {
        let openSession;
        const sessions = this.sessions;
        for (const key in sessions) {
            if (sessions[key].indexInfo.closed === -1) {
                if (openSession !== undefined) {
                    throw new Error("Datastore inconsistensy: multiple open sessions");
                }
                openSession = sessions[key];
            }
        }
    }

    updateSessionState(session) {
        const sessions = this.sessions;
        this.#removeOldChains(session);
        sessions[util.toString(session.indexInfo.baseKey)] = session;
        this.#removeOldSessions();
    }

    getSessions() {
        let list = [];
        let openSession;
        for (const k in this.sessions) {
            if (this.sessions[k].indexInfo.closed === -1) {
                openSession = this.sessions[k];
            } else {
                list.push(this.sessions[k]);
            }
        }
        list = list.sort((s1, s2) => s1.indexInfo.closed - s2.indexInfo.closed);
        if (openSession) {
            list.push(openSession);
        }
        return list;
    }

    archiveCurrentState() {
        const open_session = this.getOpenSession();
        if (open_session !== undefined) {
            console.log("closing session");
            open_session.indexInfo.closed = Date.now();
            this.updateSessionState(open_session);
        }
    }

    promoteState(session) {
        console.log("promoting session");
        session.indexInfo.closed = -1;
    }

    #removeOldChains(session) {
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
    }

    #removeOldSessions() {
        const sessions = this.sessions;
        let oldestBaseKey, oldestSession;
        while (Object.keys(sessions).length > ARCHIVED_STATES_MAX_LENGTH) {
            for (const key in sessions) {
                if (!Object.prototype.hasOwnProperty.call(sessions, key)) {
                    continue;
                }
                const session = sessions[key];
                if (
                    session.indexInfo.closed > -1 &&
                    (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)
                ) {
                    oldestBaseKey = key;
                    oldestSession = session;
                }
            }
            console.log("Deleting session closed at", oldestSession.indexInfo.closed);
            delete sessions[util.toString(oldestBaseKey)];
        }
    }

    deleteAllSessions() {
        this.sessions = {};
    }
}

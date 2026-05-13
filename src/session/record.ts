import { jsonThing, util } from "../helpers";
import { BaseKeyType } from "../types";
import { Migration, MixedSessionState, SessionRecordData } from "./types";

const ARCHIVED_STATES_MAX_LENGTH = 40;
const OLD_RATCHETS_MAX_LENGTH = 10;
const SESSION_RECORD_VERSION = "v1";

const migrations: Migration[] = [
    {
        version: "v1",
        migrate(data: SessionRecordData) {
            const sessions = data.sessions;
            if (data.registrationId) {
                for (const key in sessions) {
                    if (!sessions[key].registrationId) {
                        sessions[key].registrationId = data.registrationId!;
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

function migrate(data: SessionRecordData): void {
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
    sessions: Record<string, MixedSessionState> = {};
    version = SESSION_RECORD_VERSION;

    static deserialize(serialized: string): SessionRecord {
        const data = JSON.parse(serialized) as SessionRecordData;
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

    serialize(): string {
        return jsonThing({
            sessions: this.sessions,
            version: this.version,
        });
    }

    hasOpenSession(): boolean {
        const openSession = this.getOpenSession();
        return !!openSession && typeof openSession.registrationId === "number";
    }

    getSessionByBaseKey(baseKey: ArrayBuffer): MixedSessionState | undefined {
        const session = this.sessions[util.toString(baseKey)];
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            console.log("Tried to lookup a session using our basekey");
            return undefined;
        }
        return session;
    }

    getSessionByRemoteEphemeralKey(remoteEphemeralKey: ArrayBuffer): MixedSessionState | undefined {
        this.detectDuplicateOpenSessions();
        const sessions = this.sessions;
        const searchKey = util.toString(remoteEphemeralKey);

        let openSession: MixedSessionState | undefined;
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

    getOpenSession(): MixedSessionState | undefined {
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

    detectDuplicateOpenSessions(): void {
        let openSession: MixedSessionState | undefined;
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

    updateSessionState(session: MixedSessionState): void {
        const sessions = this.sessions;
        this.#removeOldChains(session);
        sessions[util.toString(session.indexInfo.baseKey!)] = session;
        this.#removeOldSessions();
    }

    getSessions(): MixedSessionState[] {
        let list: MixedSessionState[] = [];
        let openSession: MixedSessionState | undefined;
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

    archiveCurrentState(): void {
        const open_session = this.getOpenSession();
        if (open_session !== undefined) {
            console.log("closing session");
            open_session.indexInfo.closed = Date.now();
            this.updateSessionState(open_session);
        }
    }

    promoteState(session: MixedSessionState): void {
        console.log("promoting session");
        session.indexInfo.closed = -1;
    }

    #removeOldChains(session: MixedSessionState): void {
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

    #removeOldSessions(): void {
        const sessions = this.sessions;
        let oldestBaseKey: string | undefined;
        let oldestSession: MixedSessionState | undefined;
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
            console.log("Deleting session closed at", oldestSession!.indexInfo.closed);
            delete sessions[util.toString(oldestBaseKey!)];
        }
    }

    deleteAllSessions(): void {
        this.sessions = {};
    }
}

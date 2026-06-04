import { jsonThing, strToBytes, util } from "../helpers";
import { BaseKeyType } from "../types";
import { Migration, SessionState, SessionRecordData, SerializedSessionState } from "./types";

const ARCHIVED_STATES_MAX_LENGTH = 40;
const OLD_RATCHETS_MAX_LENGTH = 10;
const SESSION_RECORD_VERSION = "v2";

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
                    if (SessionRecord.isSessionOpen(sessions[key])) {
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
    {
        // Sessions stored before omemo:2 support predate the protocolVersion field
        // and can only be 0.3.0, the only version the library used to write.
        version: "v2",
        migrate(data: SessionRecordData) {
            for (const key in data.sessions) {
                if (data.sessions[key].protocolVersion === undefined) {
                    data.sessions[key].protocolVersion = "eu.siacs.conversations.axolotl";
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

/** Manages session state persistence, including serialization, deserialization, and lifecycle. */
export class SessionRecord {
    sessions: Record<string, SessionState> = {};
    version = SESSION_RECORD_VERSION;

    static deserialize(serialized: string): SessionRecord {
        const data = JSON.parse(serialized) as SessionRecordData;

        if (
            data.sessions === undefined ||
            data.sessions === null ||
            typeof data.sessions !== "object" ||
            Array.isArray(data.sessions)
        ) {
            throw new Error("Error deserializing SessionRecord");
        }

        if (data.version !== SESSION_RECORD_VERSION) {
            migrate(data);
        }

        const record = new SessionRecord();

        for (const key of Object.keys(data.sessions)) {
            const session = SessionRecord.deserializeSession(data.sessions[key]);
            if (session !== null) {
                record.sessions[key] = session;
            }
        }
        return record;
    }

    static deserializeSession(serialized: SerializedSessionState): SessionState | null {
        const { indexInfo, pendingPreKey, registrationId, currentRatchet: cr } = serialized;

        if (!cr || typeof cr !== "object") {
            console.warn("Skipping corrupted session state: missing currentRatchet");
            return null;
        }
        if (!indexInfo || typeof indexInfo !== "object") {
            console.warn("Skipping corrupted session state: missing indexInfo");
            return null;
        }

        const session: SessionState = {
            registrationId,
            protocolVersion: serialized.protocolVersion ?? "eu.siacs.conversations.axolotl",
            ad: typeof serialized.ad === "string" ? strToBytes(serialized.ad) : undefined,
            currentRatchet: {
                rootKey:
                    typeof cr.rootKey === "string" ? strToBytes(cr.rootKey) : new ArrayBuffer(0),
                lastRemoteEphemeralKey:
                    typeof cr.lastRemoteEphemeralKey === "string"
                        ? strToBytes(cr.lastRemoteEphemeralKey)
                        : new ArrayBuffer(0),
                previousCounter: cr.previousCounter ?? 0,
                ephemeralKeyPair: {
                    pubKey:
                        typeof cr.ephemeralKeyPair?.pubKey === "string"
                            ? strToBytes(cr.ephemeralKeyPair.pubKey)
                            : new ArrayBuffer(0),
                    privKey:
                        typeof cr.ephemeralKeyPair?.privKey === "string"
                            ? strToBytes(cr.ephemeralKeyPair.privKey)
                            : new ArrayBuffer(0),
                },
            },
            indexInfo: {
                baseKey:
                    typeof indexInfo.baseKey === "string"
                        ? strToBytes(indexInfo.baseKey)
                        : undefined,
                baseKeyType: indexInfo.baseKeyType,
                closed: indexInfo.closed ?? 0,
                remoteIdentityKey:
                    typeof indexInfo.remoteIdentityKey === "string"
                        ? strToBytes(indexInfo.remoteIdentityKey)
                        : new ArrayBuffer(0),
                remoteIdentityKeyEd:
                    typeof indexInfo.remoteIdentityKeyEd === "string"
                        ? strToBytes(indexInfo.remoteIdentityKeyEd)
                        : undefined,
            },
            oldRatchetList: (serialized.oldRatchetList ?? []).map((entry) => ({
                added: entry.added,
                ephemeralKey:
                    typeof entry.ephemeralKey === "string"
                        ? strToBytes(entry.ephemeralKey)
                        : new ArrayBuffer(0),
            })),
            pendingPreKey:
                pendingPreKey && typeof pendingPreKey.baseKey === "string"
                    ? {
                          signedKeyId: pendingPreKey.signedKeyId,
                          baseKey: strToBytes(pendingPreKey.baseKey),
                          preKeyId: pendingPreKey.preKeyId,
                      }
                    : undefined,
        };

        for (const key of Object.keys(serialized)) {
            if (
                key === "registrationId" ||
                key === "protocolVersion" ||
                key === "ad" ||
                key === "currentRatchet" ||
                key === "indexInfo" ||
                key === "oldRatchetList" ||
                key === "pendingPreKey"
            ) {
                continue;
            }
            const value = serialized[key];
            if (SessionRecord.isChainLike(value)) {
                const chain = value as Record<string, unknown>;
                const chainKey = chain.chainKey as Record<string, unknown>;
                const messageKeys = chain.messageKeys as Record<string, string>;
                session[key] = {
                    messageKeys: Object.fromEntries(
                        Object.entries(messageKeys).map(([k, v]) => [
                            Number(k),
                            typeof v === "string" ? strToBytes(v) : new ArrayBuffer(0),
                        ])
                    ),
                    chainKey: {
                        counter: (chainKey.counter as number) ?? 0,
                        key:
                            typeof chainKey.key === "string" ? strToBytes(chainKey.key) : undefined,
                    },
                    chainType: chain.chainType as number | undefined,
                };
            }
        }

        return session;
    }

    static isChainLike(value: unknown): boolean {
        return (
            typeof value === "object" &&
            value !== null &&
            "messageKeys" in value &&
            typeof (value as Record<string, unknown>).messageKeys === "object" &&
            (value as Record<string, unknown>).messageKeys !== null &&
            "chainKey" in value &&
            typeof (value as Record<string, unknown>).chainKey === "object" &&
            (value as Record<string, unknown>).chainKey !== null &&
            "chainType" in value
        );
    }

    static isSessionOpen({ indexInfo }: SessionState | SerializedSessionState): boolean {
        return indexInfo.closed === -1;
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

    getSessionByBaseKey(baseKey: ArrayBuffer | string | Uint8Array): SessionState | undefined {
        const session = this.sessions[util.toString(baseKey)];
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            console.log("Tried to lookup a session using our basekey");
            return undefined;
        }
        return session;
    }

    getSessionByRemoteEphemeralKey(remoteEphemeralKey: ArrayBuffer): SessionState | undefined {
        this.detectDuplicateOpenSessions();
        const sessions = this.sessions;
        const searchKey = util.toString(remoteEphemeralKey);

        let openSession: SessionState | undefined;
        for (const key in sessions) {
            if (!Object.prototype.hasOwnProperty.call(sessions, key)) {
                continue;
            }
            if (SessionRecord.isSessionOpen(sessions[key])) {
                openSession = sessions[key];
            }
            if (sessions[key][searchKey] !== undefined) {
                return sessions[key];
            }
        }
        return openSession;
    }

    getOpenSession(): SessionState | undefined {
        const sessions = this.sessions;
        if (sessions === undefined) {
            return undefined;
        }

        this.detectDuplicateOpenSessions();

        for (const key in sessions) {
            if (SessionRecord.isSessionOpen(sessions[key])) {
                return sessions[key];
            }
        }
        return undefined;
    }

    detectDuplicateOpenSessions(): void {
        let openSession: SessionState | undefined;
        const sessions = this.sessions;
        for (const key in sessions) {
            if (SessionRecord.isSessionOpen(sessions[key])) {
                if (openSession !== undefined) {
                    throw new Error("Datastore inconsistensy: multiple open sessions");
                }
                openSession = sessions[key];
            }
        }
    }

    updateSessionState(session: SessionState): void {
        const sessions = this.sessions;
        this.#removeOldChains(session);
        sessions[util.toString(session.indexInfo.baseKey!)] = session;
        this.#removeOldSessions();
    }

    getSessions(): SessionState[] {
        let list: SessionState[] = [];
        let openSession: SessionState | undefined;
        for (const k in this.sessions) {
            if (SessionRecord.isSessionOpen(this.sessions[k])) {
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

    promoteState(session: SessionState): void {
        console.log("promoting session");
        session.indexInfo.closed = -1;
    }

    #removeOldChains(session: SessionState): void {
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
        let oldestSession: SessionState | undefined;
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

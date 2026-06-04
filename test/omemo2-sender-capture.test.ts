import { writeFileSync } from "node:fs";
import { SessionBuilder, SessionCipher, OMEMOAddress, util } from "../src/index";
import { generateIdentity } from "./utils";
import InMemoryStore from "../src/session/store";
import { LIBOMEMO_C_VECTOR, libomemoCBobBundle } from "./omemo2-vector";

/**
 * Capture helper for the sender-direction interop confirmation (#5): libomemo.js
 * plays Alice, encrypts an omemo:2 key-exchange message to libomemo-c's committed
 * Bob bundle, and writes everything tools/dec-omemo2-vector.c needs to decrypt it
 * with libomemo-c. This is a manual, one-time step — gated behind CAPTURE_OMEMO2
 * so it never runs in CI. See tools/README.md.
 *
 *   CAPTURE_OMEMO2=1 npx vitest run test/omemo2-sender-capture.test.ts
 */
function toHex(bytes: Uint8Array): string {
    let s = "";
    for (const b of bytes) s += b.toString(16).padStart(2, "0");
    return s;
}

describe("OMEMO 2 sender-direction capture (manual)", function () {
    it.skipIf(!process.env.CAPTURE_OMEMO2)(
        "encrypts to libomemo-c's bundle and writes tools/omemo2-sender-vector.txt",
        async function () {
            const BOB = new OMEMOAddress("bob@example.org", 1);
            const aliceStore = new InMemoryStore();
            await generateIdentity(aliceStore);

            const builder = new SessionBuilder(aliceStore, BOB, "urn:xmpp:omemo:2");
            await builder.processPreKey(libomemoCBobBundle());

            const cipher = new SessionCipher(aliceStore, BOB, "urn:xmpp:omemo:2");
            const plaintext = "libomemo.js -> libomemo-c omemo:2 sender interop";
            const result = await cipher.encrypt(util.toArrayBuffer(plaintext) as ArrayBuffer);
            if (result.type !== 3) throw new Error(`expected a key-exchange message, got type ${result.type}`);

            const ciphertext = Uint8Array.from(result.body, (c) => c.charCodeAt(0));
            const v = LIBOMEMO_C_VECTOR;
            const lines = [
                `bobRegistrationId ${v.bobRegistrationId}`,
                `signedPreKeyId ${v.signedPreKeyId}`,
                `preKeyId ${v.preKeyId}`,
                `bobIdentityPriv ${v.bobIdentityPriv}`,
                `bobIdentityPub ${v.bobIdentityPub}`,
                `bobSignedPreKeyPriv ${v.bobSignedPreKeyPriv}`,
                `bobSignedPreKeyPub ${v.bobSignedPreKeyPub}`,
                `bobPreKeyPriv ${v.bobPreKeyPriv}`,
                `bobPreKeyPub ${v.bobPreKeyPub}`,
                `plaintext ${toHex(new TextEncoder().encode(plaintext))}`,
                `ciphertext ${toHex(ciphertext)}`,
            ];
            writeFileSync("tools/omemo2-sender-vector.txt", lines.join("\n") + "\n");
            console.log("wrote tools/omemo2-sender-vector.txt");
        }
    );
});

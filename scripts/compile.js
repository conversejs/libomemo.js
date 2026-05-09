import { execSync } from "child_process";

const OUTFILE = "build/curve25519_compiled.js";

const SOURCE_FILES = [
    "native/ed25519/*.c",
    "native/ed25519/additions/*.c",
    "native/ed25519/nacl_sha512/*.c",
    "native/curve25519-donna.c",
    "native/ed25519/sha512/sha2big.c",
];

const EXPORTED_FUNCTIONS = [
    "curve25519_donna",
    "curve25519_sign",
    "curve25519_verify",
    "crypto_sign_ed25519_ref10_ge_scalarmult_base",
    "sph_sha512_init",
    "malloc",
    "free",
    "xed25519_sign",
].map((name) => `'_${name}'`);

const FLAGS = [
    "-O1",
    "-Qunused-arguments",
    "-o",
    OUTFILE,
    "-Inative/ed25519/nacl_includes",
    "-Inative/ed25519",
    "-Inative/ed25519/sha512",
    "-s",
    `EXPORTED_FUNCTIONS=[${EXPORTED_FUNCTIONS.join(",")}]`,
    "-s",
    "EXPORT_ES6=1",
    "-s",
    "MODULARIZE=1",
    "-s",
    "EXPORT_NAME=Curve25519Module",
];

const command = ["emcc", ...SOURCE_FILES, ...FLAGS].join(" ");

console.log("Compiling via emscripten to " + OUTFILE);
console.log(command);

try {
    execSync(command, { stdio: "inherit" });
    console.log("Compilation complete.");
} catch (error) {
    console.error("Compilation failed.");
    process.exit(1);
}

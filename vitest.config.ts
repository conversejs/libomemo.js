import { defineConfig } from "vitest/config";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Plugin that resolves .js imports to .ts files within test/ and src/.
 */
function resolveTsFromJs() {
    return {
        name: "resolve-ts-from-js",
        resolveId(source: string, importer: string | undefined) {
            if (!source.endsWith(".js") || !importer) return null;
            const tsPath = source.replace(/\.js$/, ".ts");
            const resolved = resolve(dirname(importer), tsPath);
            try {
                readFileSync(resolved);
                return resolved;
            } catch {
                return null;
            }
        },
    };
}

/**
 * Plugin that inlines .proto files as strings (matches rollup-plugin-string).
 */
function stringPlugin() {
    return {
        name: "string",
        transform(code: string, id: string) {
            if (id.endsWith(".proto")) {
                return { code: `export default ${JSON.stringify(code)};`, map: null };
            }
        },
    };
}

/**
 * Plugin that bundles the Emscripten curve25519 module and inlines the WASM
 * binary so it doesn't need to be loaded from disk at runtime.
 */
function curveWasmInlinePlugin() {
    const wasmPath = resolve(__dirname, "build", "curve25519_compiled.wasm");
    const wasmJsPath = resolve(__dirname, "build", "curve25519_compiled.js");
    const wasmBase64 = readFileSync(wasmPath).toString("base64");

    return {
        name: "curve-wasm-inline",
        resolveId(id: string) {
            if (id.includes("curve25519_compiled") && !id.endsWith(".wasm")) {
                return wasmJsPath;
            }
            return null;
        },
        load(id: string) {
            if (id === wasmJsPath) {
                let js = readFileSync(wasmJsPath, "utf8");

                // Replace the Emscripten WASM loading with an inlined base64 version.
                const injection = `var wasmBinary = Uint8Array.from(atob("${wasmBase64}"), c => c.charCodeAt(0));`;

                // Insert after the "var wasmBinary;" declaration line
                js = js.replace(/^var wasmBinary;$/m, injection);

                // Fix __dirname not being available in ESM: replace with import.meta.url based path
                js = js.replace(
                    "scriptDirectory = __dirname + '/';",
                    `scriptDirectory = new URL('.', import.meta.url).pathname + '/';`
                );

                return js;
            }
            return null;
        },
    };
}

export default defineConfig({
    plugins: [resolveTsFromJs(), stringPlugin(), curveWasmInlinePlugin()],
    test: {
        globals: true,
        include: ["test/**/*.ts"],
        exclude: [
            "test/support/**",
            "test/utils.ts",
            "test/testvectors.ts",
            "test/identity-key-store.ts",
            "test/prekey-store.ts",
            "test/session-store.ts",
            "test/signed-prekey-store.ts",
        ],
        setupFiles: ["test/support/vitest-setup.ts"],
        testTimeout: 20000,
    },
    esbuild: {
        target: "es2020",
    },
});

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
 * The Emscripten curve25519 module is compiled with `-s SINGLE_FILE=1`, so the
 * wasm is already embedded as a data URI in the .js and needs no separate file.
 * The only thing the test runner still needs is to neutralise emcc's Node branch,
 * which runs `scriptDirectory = __dirname + '/'` at import time; `__dirname` does
 * not exist in the ES module the runner loads, so we rewrite it to an
 * import.meta.url-based path.
 */
function curveNodeShimPlugin() {
    const wasmJsPath = resolve(__dirname, "build", "curve25519_compiled.js");

    return {
        name: "curve-node-shim",
        resolveId(id: string) {
            if (id.includes("curve25519_compiled") && !id.endsWith(".wasm")) {
                return wasmJsPath;
            }
            return null;
        },
        load(id: string) {
            if (id === wasmJsPath) {
                const js = readFileSync(wasmJsPath, "utf8");
                return js.replace(
                    "scriptDirectory = __dirname + '/';",
                    `scriptDirectory = new URL('.', import.meta.url).pathname + '/';`
                );
            }
            return null;
        },
    };
}

export default defineConfig({
    plugins: [resolveTsFromJs(), stringPlugin(), curveNodeShimPlugin()],
    test: {
        globals: true,
        include: ["test/**/*.ts"],
        exclude: [
            "test/support/**",
            "test/utils.ts",
            "test/testvectors.ts",
            "test/omemo2-vector.ts",
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

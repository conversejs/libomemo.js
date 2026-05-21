import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

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

                const injection = `var wasmBinary = Uint8Array.from(atob("${wasmBase64}"), c => c.charCodeAt(0));`;

                js = js.replace(
                    /^var wasmBinary;$/m,
                    injection
                );

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
        browser: {
            enabled: true,
            provider: playwright(),
            instances: [{ browser: "chromium" }],
            headless: true,
        },
    },
    esbuild: {
        target: "es2020",
    },
});

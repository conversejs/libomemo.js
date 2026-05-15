import esbuild from "esbuild";
import { readFileSync, copyFileSync, mkdirSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(__dirname, "..", "build", "test-node");

if (!existsSync(outDir)) {
    mkdirSync(outDir, { recursive: true });
}

// Copy the WASM file so it sits next to the bundled curve25519 module
copyFileSync(
    resolve(__dirname, "..", "build", "curve25519_compiled.wasm"),
    resolve(outDir, "curve25519_compiled.wasm")
);

/**
 * Plugin that inlines .proto files as strings (matches rollup-plugin-string).
 */
function stringPlugin() {
    return {
        name: "string",
        setup(build) {
            build.onLoad({ filter: /\.proto$/ }, (args) => {
                const text = readFileSync(args.path, "utf8");
                return { contents: `export default ${JSON.stringify(text)};`, loader: "js" };
            });
        },
    };
}

/**
 * Plugin that resolves .js imports to .ts files within test/ and src/.
 */
function resolveTsFromJs() {
    return {
        name: "resolve-ts-from-js",
        setup(build) {
            build.onResolve({ filter: /\.js$/ }, (args) => {
                if (!args.importer) return null;
                const source = args.path;
                if (source.startsWith("../src/") || source.startsWith("./src/") || source.startsWith("./") || source.startsWith("../")) {
                    const tsPath = source.replace(/\.js$/, ".ts");
                    const resolved = resolve(dirname(args.importer), tsPath);
                    try {
                        readFileSync(resolved);
                        return { path: resolved };
                    } catch {
                        return null;
                    }
                }
                return null;
            });
        },
    };
}

/**
 * Plugin that bundles the Emscripten curve25519 module and inlines the WASM
 * binary so it doesn't need to be loaded from disk at runtime.
 */
function curveWasmInlinePlugin() {
    const wasmPath = resolve(__dirname, "..", "build", "curve25519_compiled.wasm");
    const wasmJsPath = resolve(__dirname, "..", "build", "curve25519_compiled.js");
    const wasmBase64 = readFileSync(wasmPath).toString("base64");

    return {
        name: "curve-wasm-inline",
        setup(build) {
            build.onResolve({ filter: /curve25519_compiled$/ }, () => {
                return { path: wasmJsPath, namespace: "curve-inline" };
            });
            build.onLoad({ filter: /curve25519_compiled\.js$/, namespace: "curve-inline" }, () => {
                let js = readFileSync(wasmJsPath, "utf8");

                // Replace the Emscripten WASM loading with an inlined base64 version.
                // We inject wasmBinary before the module code runs so it skips fetch/read.
                const injection = `var wasmBinary = typeof globalThis !== 'undefined' && globalThis.__curve25519_wasm__
                    ? globalThis.__curve25519_wasm__
                    : Uint8Array.from(atob("${wasmBase64}"), c => c.charCodeAt(0));
                `;

                // Insert after the "var wasmBinary;" declaration line
                js = js.replace(
                    /^var wasmBinary;$/m,
                    injection.trim()
                );

                // Fix __dirname not being available in ESM: replace with import.meta.url based path
                js = js.replace(
                    "scriptDirectory = __dirname + '/';",
                    `scriptDirectory = new URL('.', import.meta.url).pathname + '/';`
                );

                return { contents: js, loader: "js" };
            });
        },
    };
}

await esbuild.build({
    entryPoints: ["test/**/*.ts"],
    bundle: true,
    platform: "node",
    target: "es2020",
    format: "esm",
    outdir: outDir,
    sourcemap: true,
    plugins: [resolveTsFromJs(), stringPlugin(), curveWasmInlinePlugin()],
    tsconfig: "./tsconfig.json",
});

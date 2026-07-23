import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";
import typescript from "@rollup/plugin-typescript";
import { dts } from "rollup-plugin-dts";
import esbuild from "rollup-plugin-esbuild";
import { fileURLToPath } from "url";

// The wasm-free curve stub, and the real wasm-backed curve module it stands in
// for. In the worker-client build every import that resolves to the real module
// is redirected to the stub (see stubCurvePlugin), so no WebAssembly is bundled.
const workerClientCurveStub = fileURLToPath(
    new URL("./src/curve.worker-client.ts", import.meta.url)
);
const realCurveModule = fileURLToPath(new URL("./src/curve.ts", import.meta.url));

export function onwarn(warning, warn) {
    if (
        warning.code === "CIRCULAR_DEPENDENCY" &&
        warning.message.includes("node_modules/protobufjs")
    )
        return;
    warn(warning);
}

/**
 * The Emscripten module is compiled with `-s SINGLE_FILE=1` (scripts/compile.js),
 * so the wasm is embedded as an in-JS data URI and needs no sibling asset or path
 * rewriting. One init-time hazard remains: emcc's Node branch runs
 * `scriptDirectory = __dirname + '/'` unconditionally, and `__dirname` does not
 * exist in an ES module, so importing the bundle under Node ESM would throw
 * `ReferenceError: __dirname is not defined` before any wasm work happens. This
 * plugin neutralises that single line with an environment-agnostic expression.
 * (scriptDirectory is unused for wasm loading once the binary is inlined.)
 */
function patchScriptDirectoryPlugin() {
    return {
        name: "patch-script-directory",
        transform(code, id) {
            if (!id.includes("curve25519_compiled")) return null;

            code = code.replace(
                /scriptDirectory = __dirname \+ '\/';/,
                `scriptDirectory = (typeof document !== 'undefined' && document.currentScript) ? document.currentScript.src.substring(0, document.currentScript.src.lastIndexOf('/') + 1) : '';`
            );

            return { code, map: { mappings: "", sources: [], names: [], version: 3 } };
        },
    };
}

/**
 * Redirect the wasm-backed curve module to the wasm-free stub for the
 * worker-client build. Unlike a plain `{ find: "./curve" }` alias, this matches on
 * the *resolved* module path, so a future importer that reaches curve.ts via
 * "../curve", a subdirectory, or an explicit ".js"/".ts" extension is still caught
 * instead of silently pulling the wasm back into a build whose whole purpose is to
 * omit it. The cheap name pre-filter keeps the extra `this.resolve` off every
 * unrelated specifier.
 */
function stubCurvePlugin() {
    return {
        name: "stub-curve",
        async resolveId(source, importer, options) {
            if (source === workerClientCurveStub) return null; // never redirect the stub itself
            if (!/(^|[\\/])curve(\.[jt]s)?$/.test(source)) return null;

            const resolved = await this.resolve(source, importer, { ...options, skipSelf: true });
            if (resolved && !resolved.external && resolved.id === realCurveModule) {
                return workerClientCurveStub;
            }
            return null;
        },
    };
}

/**
 * Fail the worker-client build if any WebAssembly leaks into its output. This is
 * the actual enforcement behind "no wasm on the main thread": if an import ever
 * slips past stubCurvePlugin, the build breaks loudly here instead of shipping a
 * bundle that quietly re-embeds the ~100KB inlined wasm. `Curve25519Module` is the
 * Emscripten EXPORT_NAME; the data-URI mime is how SINGLE_FILE inlines the binary.
 */
function assertWasmFreePlugin() {
    return {
        name: "assert-wasm-free",
        generateBundle(_options, bundle) {
            for (const [fileName, chunk] of Object.entries(bundle)) {
                if (chunk.type !== "chunk") continue;
                if (
                    chunk.code.includes("Curve25519Module") ||
                    chunk.code.includes("application/octet-stream;base64")
                ) {
                    this.error(
                        `worker-client build leaked WebAssembly into ${fileName}: an import ` +
                            `bypassed the curve stub (see stubCurvePlugin in rollup.config.js).`
                    );
                }
            }
        },
    };
}

export default [
    {
        input: "src/index.ts",
        output: [
            {
                file: "dist/libomemo.esm.js",
                format: "es",
                sourcemap: true,
            },
            {
                file: "dist/libomemo.umd.cjs",
                format: "umd",
                name: "libomemo",
                exports: "named",
                sourcemap: true,
            },
        ],
        plugins: [
            string({ include: "**/*.proto" }),
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
        ],
        external: [],
        onwarn,
    },
    {
        input: "src/index.ts",
        output: [
            {
                file: "dist/libomemo.esm.min.js",
                format: "es",
                sourcemap: true,
            },
            {
                file: "dist/libomemo.umd.min.cjs",
                format: "umd",
                name: "libomemo",
                exports: "named",
                sourcemap: true,
            },
        ],
        plugins: [
            string({ include: "**/*.proto" }),
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
            esbuild({ minify: true }),
        ],
        external: [],
        onwarn,
    },
    {
        // The worker-client build: same public API as the default build, but the
        // wasm-backed `./curve` is redirected to a stub (stubCurvePlugin), so no
        // WebAssembly is bundled, and assertWasmFreePlugin fails the build if any
        // slips through. Consumers import it as `libomemo.js/worker-client`, must
        // call startWorker() before any crypto, and serve the (wasm-carrying)
        // worker. No patchScriptDirectoryPlugin: the stub imports no Emscripten module.
        input: "src/index.ts",
        output: {
            file: "dist/libomemo.worker-client.esm.js",
            format: "es",
            sourcemap: true,
        },
        plugins: [
            stubCurvePlugin(),
            string({ include: "**/*.proto" }),
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            assertWasmFreePlugin(),
        ],
        external: [],
        onwarn,
    },
    {
        input: "src/curve25519_worker.ts",
        output: {
            file: "dist/libomemo-worker.js",
            format: "iife",
            sourcemap: true,
            banner: "// Shim for Emscripten: provide document in worker context\nif (typeof document === 'undefined') { self.document = { baseURI: self.location.href }; }",
        },
        plugins: [
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
        ],
        onwarn,
    },
    {
        input: "src/curve25519_worker.ts",
        output: {
            file: "dist/libomemo-worker.min.js",
            format: "iife",
            sourcemap: true,
            banner: "// Shim for Emscripten: provide document in worker context\nif (typeof document === 'undefined') { self.document = { baseURI: self.location.href }; }",
        },
        plugins: [
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
            esbuild({ minify: true }),
        ],
        onwarn,
    },
    {
        input: "build/dts/index.d.ts",
        output: {
            file: "dist/index.d.ts",
            format: "es",
        },
        plugins: [dts()],
        onwarn,
    },
];

import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";
import typescript from "@rollup/plugin-typescript";
import { dts } from "rollup-plugin-dts";
import { readFileSync } from "fs";
import { resolve as resolvePath, basename } from "path";
import { fileURLToPath } from "url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

export function onwarn(warning, warn) {
    if (
        warning.code === "CIRCULAR_DEPENDENCY" &&
        warning.message.includes("node_modules/protobufjs")
    )
        return;
    warn(warning);
}

/**
 * Plugin that emits the Emscripten WASM file as a sibling asset
 * and rewrites the module's wasm path to a relative import.meta.url
 * reference that resolves correctly in the output.
 */
function emitWasmPlugin() {
    const wasmPath = resolvePath(__dirname, "build", "curve25519_compiled.wasm");
    const wasmName = basename(wasmPath);

    return {
        name: "emit-wasm",
        transform(code, id) {
            if (!id.includes("curve25519_compiled")) return null;

            code = code.replace(
                /scriptDirectory = __dirname \+ '\/';/,
                `scriptDirectory = (typeof document !== 'undefined' && document.currentScript) ? document.currentScript.src.substring(0, document.currentScript.src.lastIndexOf('/') + 1) : '';`
            );

            code = code.replace(
                /wasmBinaryFile = new URL\('curve25519_compiled\.wasm', import\.meta\.url\)\.toString\(\);/,
                `wasmBinaryFile = '${wasmName}';`
            );

            return { code, map: { mappings: "", sources: [], names: [], version: 3 } };
        },
        generateBundle() {
            this.emitFile({
                type: "asset",
                fileName: wasmName,
                source: readFileSync(wasmPath),
            });
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
                file: "dist/libomemo.umd.js",
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
            emitWasmPlugin(),
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
            emitWasmPlugin(),
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
